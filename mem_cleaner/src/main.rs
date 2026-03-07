use aya::maps::perf::PerfEventArray; // 注意：去掉了 Async
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::Bpf;
use bytes::BytesMut;
use mem_cleaner_common::ProcessEvent;

use fxhash::FxHashSet;
use nix::sys::epoll::{epoll_create1, epoll_ctl, epoll_wait, EpollCreateFlags, EpollEvent, EpollFlags, EpollOp};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

use std::collections::{HashMap, VecDeque};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use time::macros::format_description;
use time::{format_description::FormatItem, Date, OffsetDateTime};

// === 配置常量 ===
const OOM_SCORE_THRESHOLD: i32 = 800;
const INIT_DELAY_SECS: u64 = 2;       // 观察期 (秒)
const DEFAULT_INTERVAL: u64 = 30;     // 轮询查杀间隔 (秒)
const MIN_APP_UID: u32 = 10000;       // 系统进程红线

#[repr(C, align(8))]
struct AlignedBpf([u8; include_bytes!("mem_cleaner_ebpf.o").len()]);
static BPF_BYTES: AlignedBpf = AlignedBpf(*include_bytes!("mem_cleaner_ebpf.o"));

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum WhitelistRule {
    Exact(String),
    Prefix(String),
}

struct AppConfig {
    interval: u64,
    whitelist: FxHashSet<WhitelistRule>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <config_path>[log_path]", args[0]);
        std::process::exit(1);
    }

    let config_path = &args[1];
    let log_path = if args.len() > 2 { Some(args[2].clone()) } else { None };

    println!("⚡ 初始化 Android 进程压制器 (单线程 Epoll 极致省电版) ⚡");

    let config = Arc::new(load_config(config_path));
    let mut logger = Logger::new(log_path);
    if let Some(l) = &mut logger { l.write_startup(); }

    println!("📦 加载 eBPF 模块...");
    let mut bpf = Bpf::load(&BPF_BYTES.0)?;

    let program: &mut TracePoint = bpf.program_mut("sched_process_fork").unwrap().try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_fork")?;
    println!("✅ eBPF 挂载成功: 仅拦截 UID 0 (Zygote) 孵化");

    // 注意这里使用同步的 PerfEventArray
    let mut perf_array = PerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;

    // --- Epoll 核心初始化 ---
    let epfd = epoll_create1(EpollCreateFlags::EPOLL_CLOEXEC)?;
    let mut perf_buffers = HashMap::new();

    for cpu_id in online_cpus()? {
        let buf = perf_array.open(cpu_id, None)?;
        let fd = buf.as_raw_fd();
        
        // 注册到 epoll，token (也就是 event.data) 设为 cpu_id
        let mut event = EpollEvent::new(EpollFlags::EPOLLIN, cpu_id as u64);
        epoll_ctl(epfd, EpollOp::EpollCtlAdd, fd, &mut event)?;
        
        perf_buffers.insert(cpu_id as u64, buf);
    }

    println!("🎧 Epoll 引擎就绪，接管所有 CPU 核心中断，进入极致省电模式...");

    // === 核心数据结构 ===
    // 监控名单
    let mut monitoring_pids: FxHashSet<u32> = FxHashSet::default();
    // 待处理队列 (PID, 发现时间)
    let mut pending_queue: VecDeque<(u32, Instant)> = VecDeque::new();
    
    // 事件复用的缓冲区，避免运行时内存分配
    let mut event_buffers = vec![BytesMut::with_capacity(1024); 10];
    let mut epoll_events = [EpollEvent::empty(); 16];

    // 定时器标记
    let mut next_cleanup_time = Instant::now() + Duration::from_secs(config.interval);

    // ==========================================
    // 🔥 主事件循环 (Event Loop) 🔥
    // ==========================================
    loop {
        let now = Instant::now();

        // 1. 处理 Pending 队列中成熟的进程 (经过了 2 秒等待的)
        while let Some(&(pid, add_time)) = pending_queue.front() {
            if now.duration_since(add_time).as_secs() >= INIT_DELAY_SECS {
                pending_queue.pop_front();
                
                // 执行安全检查
                if let Some(uid) = get_process_uid(pid) {
                    if uid >= MIN_APP_UID {
                        let cmdline = get_cmdline(pid);
                        if !cmdline.is_empty() && cmdline.contains(':') && !cmdline.contains("zygote") && !is_in_whitelist(&cmdline, &config.whitelist) {
                            monitoring_pids.insert(pid);
                        }
                    }
                }
            } else {
                break; // 队列是有序的，第一个没熟，后面的肯定没熟
            }
        }

        // 2. 处理周期性的清理任务 (删除 Doze 判断，直接执行)
        if now >= next_cleanup_time {
            let mut pids_to_remove = Vec::new();
            let mut killed_in_this_round = Vec::new();

            for &pid in &monitoring_pids {
                match get_process_uid(pid) {
                    Some(uid) if uid < MIN_APP_UID => { pids_to_remove.push(pid); continue; },
                    None => { pids_to_remove.push(pid); continue; },
                    _ => {}
                }

                let cmdline = get_cmdline(pid);
                if cmdline.is_empty() {
                    pids_to_remove.push(pid);
                    continue;
                }

                let score = get_oom_score(pid);
                if score >= OOM_SCORE_THRESHOLD {
                    if kill(Pid::from_raw(pid as i32), Signal::SIGKILL).is_ok() {
                        killed_in_this_round.push(format!("PID:{} | OOM:{} | {}", pid, score, cmdline));
                        pids_to_remove.push(pid);
                    } else {
                        pids_to_remove.push(pid);
                    }
                }
            }

            if !killed_in_this_round.is_empty() {
                if let Some(l) = &mut logger { l.write_cleanup(&killed_in_this_round); }
            }

            for pid in pids_to_remove {
                monitoring_pids.remove(&pid);
            }

            // 重置清理时间，依赖 Instant 原生适配 Doze
            next_cleanup_time = now + Duration::from_secs(config.interval);
        }

        // 3. 计算下一次醒来的超时时间 (Timeout)
        let now = Instant::now();
        // 距离下次周期清理还有多久
        let mut timeout_ms = next_cleanup_time.saturating_duration_since(now).as_millis() as isize;

        // 如果队列里有进程等着变熟，对比一下时间，取最近的一个作为超时时间
        if let Some(&(_, add_time)) = pending_queue.front() {
            let mature_time = add_time + Duration::from_secs(INIT_DELAY_SECS);
            let pending_timeout = mature_time.saturating_duration_since(now).as_millis() as isize;
            if pending_timeout < timeout_ms {
                timeout_ms = pending_timeout;
            }
        }

        // 4. 🔥 核心：阻塞挂起线程，让出 CPU 🔥
        // 直到 eBPF 有新事件产生，或者 Timeout 超时到了我们设定的时间，才会唤醒
        match epoll_wait(epfd, &mut epoll_events, timeout_ms) {
            Ok(n) => {
                // 如果 n == 0，说明是超时唤醒（该处理队列或者查杀了），进入下一轮即可
                // 如果 n > 0，说明 eBPF 发来了数据
                for i in 0..n {
                    let cpu_id = epoll_events[i].data();
                    if let Some(buf) = perf_buffers.get_mut(&cpu_id) {
                        // 同步读取当前缓存中的所有事件
                        if let Ok(events) = buf.read_events(&mut event_buffers) {
                            for j in 0..events.read {
                                let ptr = event_buffers[j].as_ptr() as *const ProcessEvent;
                                let event = unsafe { std::ptr::read_unaligned(ptr) };
                                
                                // 扔进处理队列，记录当前时间戳
                                pending_queue.push_back((event.pid, Instant::now()));
                            }
                        }
                    }
                }
            }
            Err(e) if e == nix::errno::Errno::EINTR => {
                // 被系统中断唤醒，无视，继续循环
                continue;
            }
            Err(e) => {
                eprintln!("Epoll error: {:?}", e);
                break;
            }
        }
    }

    Ok(())
}

// ================== 辅助函数 (保持纯净) ==================
fn get_process_uid(pid: u32) -> Option<u32> {
    fs::metadata(format!("/proc/{}", pid)).ok().map(|m| m.uid())
}

fn get_oom_score(pid: u32) -> i32 {
    fs::read_to_string(format!("/proc/{}/oom_score_adj")).ok()
        .and_then(|c| c.trim().parse::<i32>().ok()).unwrap_or(-1000)
}

fn get_cmdline(pid: u32) -> String {
    fs::read(format!("/proc/{}/cmdline")).ok()
        .and_then(|c| c.split(|&ch| ch == 0).next().map(|s| String::from_utf8_lossy(s).into_owned()))
        .unwrap_or_default()
}

fn is_in_whitelist(cmdline: &str, whitelist: &FxHashSet<WhitelistRule>) -> bool {
    if whitelist.contains(&WhitelistRule::Exact(cmdline.to_string())) { return true; }
    whitelist.iter().any(|r| if let WhitelistRule::Prefix(p) = r { cmdline.starts_with(p) } else { false })
}

fn load_config(path: &str) -> AppConfig {
    let mut interval = DEFAULT_INTERVAL;
    let mut whitelist = FxHashSet::default();
    if let Ok(content) = fs::read_to_string(path) {
        let mut in_wl = false;
        for line in content.lines().map(|l| l.trim()).filter(|l| !l.is_empty() && !l.starts_with('#')) {
            if line.starts_with("interval:") {
                if let Some(v) = line.split(':').nth(1).and_then(|v| v.trim().parse().ok()) { interval = v; }
                in_wl = false;
            } else if line.starts_with("whitelist:") {
                in_wl = true;
                if let Some(v) = line.split(':').nth(1) { parse_whitelist_rules(v, &mut whitelist); }
            } else if in_wl {
                parse_whitelist_rules(line, &mut whitelist);
            }
        }
    }
    AppConfig { interval, whitelist }
}

fn parse_whitelist_rules(line: &str, whitelist: &mut FxHashSet<WhitelistRule>) {
    for pkg in line.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
        if let Some(p) = pkg.strip_suffix(":*") { whitelist.insert(WhitelistRule::Prefix(p.to_string())); } 
        else { whitelist.insert(WhitelistRule::Exact(pkg.to_string())); }
    }
}

static TIME_FMT: &[FormatItem<'static>] = format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");
fn now_fmt() -> String { OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc()).format(TIME_FMT).unwrap_or_default() }

struct Logger { path: std::path::PathBuf, last_write_date: Option<Date> }
impl Logger {
    fn new(path: Option<String>) -> Option<Self> { path.map(|p| Self { path: std::path::PathBuf::from(p), last_write_date: None }) }
    fn open_writer(&mut self) -> Option<BufWriter<File>> {
        let today = OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc()).date();
        let mut trunc = false;
        if self.last_write_date != Some(today) {
            if let Ok(m) = fs::metadata(&self.path).and_then(|m| m.modified()) {
                if OffsetDateTime::from(m).date() != today { trunc = true; }
            } else { trunc = true; }
            self.last_write_date = Some(today);
        }
        OpenOptions::new().create(true).write(true).append(!trunc).truncate(trunc).open(&self.path).ok().map(BufWriter::new)
    }
    fn write_startup(&mut self) {
        if let Some(mut w) = self.open_writer() {
            let _ = writeln!(w, "=== 启动时间: {} ===\n⚡ eBPF 进程压制 (单线程 Epoll 版) 已启动 ⚡\n", now_fmt());
        }
    }
    fn write_cleanup(&mut self, killed_list: &[String]) {
        if let Some(mut w) = self.open_writer() {
            let _ = writeln!(w, "=== 清理时间: {} ===", now_fmt());
            for pkg in killed_list { let _ = writeln!(w, "已清理: {}", pkg); }
            let _ = writeln!(w);
        }
    }
}
