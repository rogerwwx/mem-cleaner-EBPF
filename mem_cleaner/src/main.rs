use aya::maps::perf::PerfEventArray;
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
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use time::macros::format_description;
use time::{format_description::FormatItem, Date, OffsetDateTime};

// === 配置常量 ===
const OOM_SCORE_THRESHOLD: i32 = 800;
const INIT_DELAY_SECS: u64 = 2;
const DEFAULT_INTERVAL: u64 = 30;
const MIN_APP_UID: u32 = 10000;
// 线程间通道容量，防止内存溢出
const CHANNEL_CAPACITY: usize = 1024;

#[repr(C, align(8))]
struct AlignedBpf([u8; include_bytes!("mem_cleaner_ebpf.o").len()]);
static BPF_BYTES: AlignedBpf = AlignedBpf(*include_bytes!("mem_cleaner_ebpf.o"));

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum WhitelistRule {
    Exact(String),
    Prefix(String),
}

#[derive(Debug, Clone)]
struct AppConfig {
    interval: u64,
    whitelist: FxHashSet<WhitelistRule>,
}

// ================== 主函数：线程初始化与启动 ==================
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <config_path>[log_path]", args[0]);
        std::process::exit(1);
    }

    let config_path = &args[1];
    let log_path = if args.len() > 2 { Some(args[2].clone()) } else { None };

    println!("⚡ 初始化 Android 进程压制器 (双线程 Epoll 高性能版) ⚡");

    // 🔥 Arc 正确用法：跨线程只读共享配置，线程安全
    let config = Arc::new(load_config(config_path));
    // 线程间通信通道：IO线程生产事件，业务线程消费事件
    let (event_sender, event_receiver) = mpsc::sync_channel::<ProcessEvent>(CHANNEL_CAPACITY);

    // ================== 1. 启动 IO 线程（epoll 专属） ==================
    let io_thread_handle = thread::Builder::new()
        .name("ebpf-io-thread".to_string())
        .spawn(move || -> Result<(), Box<dyn std::error::Error>> {
            println!("📦 [IO线程] 加载 eBPF 模块...");
            let mut bpf = Bpf::load(&BPF_BYTES.0)?;

            // 挂载 tracepoint
            let program: &mut TracePoint = bpf.program_mut("sched_process_fork").unwrap().try_into()?;
            program.load()?;
            program.attach("sched", "sched_process_fork")?;
            println!("✅ [IO线程] eBPF 挂载成功: 仅拦截 UID 0 (Zygote) 孵化");

            // 初始化 PerfEventArray
            let mut perf_array = PerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;

            // Epoll 初始化
            let epfd = epoll_create1(EpollCreateFlags::EPOLL_CLOEXEC)?;
            let mut perf_buffers = HashMap::new();

            // 为所有在线 CPU 注册事件缓冲区
            for cpu_id in online_cpus()? {
                let buf = perf_array.open(cpu_id, None)?;
                let fd = buf.as_raw_fd();
                let mut event = EpollEvent::new(EpollFlags::EPOLLIN, cpu_id as u64);
                epoll_ctl(epfd, EpollOp::EpollCtlAdd, fd, &mut event)?;
                perf_buffers.insert(cpu_id as u64, buf);
            }

            println!("🎧 [IO线程] Epoll 引擎就绪，进入事件监听循环...");

            // 事件缓冲区复用
            let mut event_buffers = vec![BytesMut::with_capacity(1024); 10];
            let mut epoll_events = [EpollEvent::empty(); 16];

            // 🔥 IO 线程核心循环：永久阻塞监听事件，无任何耗时操作
            loop {
                // 永久阻塞，直到有 eBPF 事件到来，完全不占用 CPU
                match epoll_wait(epfd, &mut epoll_events, -1) {
                    Ok(n) => {
                        for i in 0..n {
                            let cpu_id = epoll_events[i].data();
                            if let Some(buf) = perf_buffers.get_mut(&cpu_id) {
                                if let Ok(events) = buf.read_events(&mut event_buffers) {
                                    for j in 0..events.read {
                                        let ptr = event_buffers[j].as_ptr() as *const ProcessEvent;
                                        let event = unsafe { std::ptr::read_unaligned(ptr) };
                                        // 把事件转发给业务线程，不做任何额外处理
                                        let _ = event_sender.send(event);
                                    }
                                }
                            }
                        }
                    }
                    Err(e) if e == nix::errno::Errno::EINTR => continue,
                    Err(e) => {
                        eprintln!("[IO线程] Epoll 致命错误: {:?}", e);
                        break;
                    }
                }
            }

            Ok(())
        })?;

    // ================== 2. 启动业务处理线程 ==================
    let business_thread_handle = thread::Builder::new()
        .name("business-thread".to_string())
        .spawn(move || {
            let mut logger = Logger::new(log_path);
            if let Some(l) = &mut logger { l.write_startup(); }

            println!("✅ [业务线程] 初始化完成，进入处理循环...");

            // 业务线程专属数据，无多线程竞争，无需锁
            let mut monitoring_pids: FxHashSet<u32> = FxHashSet::default();
            let mut pending_queue: VecDeque<(u32, Instant)> = VecDeque::new();
            let mut next_cleanup_time = Instant::now() + Duration::from_secs(config.interval);

            // 🔥 业务线程核心循环
            loop {
                let now = Instant::now();

                // 1. 计算超时时间：取「pending成熟时间」和「清理时间」的最小值
                let mut timeout_ms = next_cleanup_time.saturating_duration_since(now).as_millis();
                if let Some(&(_, add_time)) = pending_queue.front() {
                    let mature_time = add_time + Duration::from_secs(INIT_DELAY_SECS);
                    let pending_timeout = mature_time.saturating_duration_since(now).as_millis();
                    timeout_ms = timeout_ms.min(pending_timeout);
                }

                // 2. 等待新事件，超时自动唤醒处理定时任务
                match event_receiver.recv_timeout(Duration::from_millis(timeout_ms)) {
                    // 收到新的 fork 事件，加入 pending 队列
                    Ok(event) => {
                        pending_queue.push_back((event.pid, Instant::now()));
                    }
                    // 超时唤醒，处理定时任务
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    // 通道断开（IO线程退出），终止业务线程
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        eprintln!("[业务线程] IO 线程已退出，终止运行");
                        break;
                    }
                }

                let now = Instant::now();

                // 3. 处理成熟的 pending 进程（2秒观察期）
                while let Some(&(pid, add_time)) = pending_queue.front() {
                    if now.duration_since(add_time).as_secs() >= INIT_DELAY_SECS {
                        pending_queue.pop_front();
                        
                        // 安全检查：只处理普通应用进程
                        if let Some(uid) = get_process_uid(pid) {
                            if uid >= MIN_APP_UID {
                                let cmdline = get_cmdline(pid);
                                if !cmdline.is_empty() 
                                    && cmdline.contains(':') 
                                    && !cmdline.contains("zygote") 
                                    && !is_in_whitelist(&cmdline, &config.whitelist) 
                                {
                                    monitoring_pids.insert(pid);
                                }
                            }
                        }
                    } else {
                        break; // 队列有序，第一个没熟后面的都没熟
                    }
                }

                // 4. 处理周期性清理任务
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

                    // 写日志
                    if !killed_in_this_round.is_empty() {
                        if let Some(l) = &mut logger { l.write_cleanup(&killed_in_this_round); }
                    }

                    // 移除失效的 PID
                    for pid in pids_to_remove {
                        monitoring_pids.remove(&pid);
                    }

                    // 重置清理时间
                    next_cleanup_time = now + Duration::from_secs(config.interval);
                }
            }
        })?;

    // 等待线程退出
    let _ = io_thread_handle.join();
    let _ = business_thread_handle.join();

    Ok(())
}

// ================== 纯函数辅助工具（无状态，线程安全） ==================
fn get_process_uid(pid: u32) -> Option<u32> {
    fs::metadata(format!("/proc/{}", pid)).ok().map(|m| m.uid())
}

fn get_oom_score(pid: u32) -> i32 {
    fs::read_to_string(format!("/proc/{}/oom_score_adj", pid))
        .ok()
        .and_then(|c| c.trim().parse::<i32>().ok())
        .unwrap_or(-1000)
}

fn get_cmdline(pid: u32) -> String {
    fs::read(format!("/proc/{}/cmdline", pid))
        .ok()
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
fn now_fmt() -> String {
    OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc()).format(TIME_FMT).unwrap_or_default()
}

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
            let _ = writeln!(w, "=== 启动时间: {} ===\n⚡ eBPF 进程压制 (双线程 Epoll 版) 已启动 ⚡\n", now_fmt());
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
