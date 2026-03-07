use aya::maps::perf::PerfEventArray;
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::Bpf;
use bytes::BytesMut;
use mem_cleaner_common::ProcessEvent;

use fxhash::FxHashSet;
// 🚨 Nix 引用更新：彻底移除废弃函数和 EpollOp
use nix::sys::epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

use std::collections::{HashMap, VecDeque};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::os::unix::fs::MetadataExt;
// 🚨 AsFd trait 需要被引入
use std::os::unix::io::AsFd;
use std::sync::mpsc::{self, RecvTimeoutError};
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

    let config = Arc::new(load_config(&args[1]));
    let mut logger = Logger::new(if args.len() > 2 {
        Some(args[2].clone())
    } else {
        None
    });
    if let Some(l) = &mut logger {
        l.write_startup();
    }

    println!("⚡ 初始化 Android 进程压制器 (双线程 Epoll 最终版) ⚡");

    println!("📦 加载 eBPF 模块...");
    let mut bpf = Bpf::load(&BPF_BYTES.0)?;

    let program: &mut TracePoint = bpf.program_mut("sched_process_fork").unwrap().try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_fork")?;
    println!("✅ eBPF 挂载成功: 仅拦截 UID 0 (Zygote) 孵化");

    let mut perf_array = PerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;

    // ==========================================
    // 🧵 工作线程 (业务逻辑)
    // ==========================================
    let (tx, rx) = mpsc::channel::<u32>();

    let worker_config = config.clone();
    thread::spawn(move || {
        let mut monitoring_pids: FxHashSet<u32> = FxHashSet::default();
        let mut pending_queue: VecDeque<(u32, Instant)> = VecDeque::new();
        let mut next_cleanup = Instant::now() + Duration::from_secs(worker_config.interval);

        println!("🛠️  业务线程已启动...");

        loop {
            let now = Instant::now();
            let mut timeout = next_cleanup.saturating_duration_since(now);

            if let Some(&(_, add_time)) = pending_queue.front() {
                let mature_time = add_time + Duration::from_secs(INIT_DELAY_SECS);
                let time_to_mature = mature_time.saturating_duration_since(now);
                if time_to_mature < timeout {
                    timeout = time_to_mature;
                }
            }

            if timeout.is_zero() {
                while let Ok(pid) = rx.try_recv() {
                    pending_queue.push_back((pid, Instant::now()));
                }
            } else {
                match rx.recv_timeout(timeout) {
                    Ok(pid) => {
                        pending_queue.push_back((pid, Instant::now()));
                        while let Ok(p) = rx.try_recv() {
                            pending_queue.push_back((p, Instant::now()));
                        }
                    }
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => break,
                }
            }

            let now = Instant::now();
            while let Some(&(pid, add_time)) = pending_queue.front() {
                if now.duration_since(add_time).as_secs() >= INIT_DELAY_SECS {
                    pending_queue.pop_front();
                    if let Some(uid) = get_process_uid(pid) {
                        if uid >= MIN_APP_UID {
                            let cmdline = get_cmdline(pid);
                            if !cmdline.is_empty()
                                && cmdline.contains(':')
                                && !cmdline.contains("zygote")
                                && !is_in_whitelist(&cmdline, &worker_config.whitelist)
                            {
                                monitoring_pids.insert(pid);
                            }
                        }
                    }
                } else {
                    break;
                }
            }
            if now >= next_cleanup {
                let mut pids_to_remove = Vec::new();
                let mut killed_in_this_round = Vec::new();
                for &pid in &monitoring_pids {
                    match get_process_uid(pid) {
                        Some(uid) if uid < MIN_APP_UID => {
                            pids_to_remove.push(pid);
                            continue;
                        }
                        None => {
                            pids_to_remove.push(pid);
                            continue;
                        }
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
                            killed_in_this_round
                                .push(format!("PID:{} | OOM:{} | {}", pid, score, cmdline));
                            pids_to_remove.push(pid);
                        } else {
                            pids_to_remove.push(pid);
                        }
                    }
                }
                if !killed_in_this_round.is_empty() {
                    if let Some(l) = &mut logger {
                        l.write_cleanup(&killed_in_this_round);
                    }
                }
                for pid in pids_to_remove {
                    monitoring_pids.remove(&pid);
                }
                next_cleanup = Instant::now() + Duration::from_secs(worker_config.interval);
            }
        }
    });

    // ==========================================
    // 🎯 主线程 (Epoll I/O)
    // ==========================================
    let epoller = Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC)?;
    let mut perf_buffers = HashMap::new();

    for cpu_id in online_cpus()? {
        let buf = perf_array.open(cpu_id, None)?;
        let mut event = EpollEvent::new(EpollFlags::EPOLLIN, cpu_id as u64);
        epoller.add(buf.as_fd(), event)?;
        perf_buffers.insert(cpu_id as u64, buf);
    }

    println!("🎧 Epoll 监听线程就绪...");

    let mut event_buffers = vec![BytesMut::with_capacity(1024); 10];
    let mut epoll_events = [EpollEvent::empty(); 16];

    loop {
        // 🔥 终极修复：使用 None 代表永久阻塞，不再使用 C 风格的 -1
        match epoller.wait(&mut epoll_events, None) {
            Ok(n) => {
                for i in 0..n {
                    let cpu_id = epoll_events[i].data();
                    if let Some(buf) = perf_buffers.get_mut(&cpu_id) {
                        if let Ok(events) = buf.read_events(&mut event_buffers) {
                            for j in 0..events.read {
                                let ptr = event_buffers[j].as_ptr() as *const ProcessEvent;
                                let event = unsafe { std::ptr::read_unaligned(ptr) };
                                let _ = tx.send(event.pid);
                            }
                        }
                    }
                }
            }
            Err(e) if e == nix::errno::Errno::EINTR => continue,
            Err(e) => {
                eprintln!("Epoll Error: {:?}", e);
                break;
            }
        }
    }

    Ok(())
}

// ================== 辅助函数 (保持不变) ==================

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
        .and_then(|c| {
            c.split(|&ch| ch == 0)
                .next()
                .map(|s| String::from_utf8_lossy(s).into_owned())
        })
        .unwrap_or_default()
}

fn is_in_whitelist(cmdline: &str, whitelist: &FxHashSet<WhitelistRule>) -> bool {
    if whitelist.contains(&WhitelistRule::Exact(cmdline.to_string())) {
        return true;
    }
    whitelist.iter().any(|r| {
        if let WhitelistRule::Prefix(p) = r {
            cmdline.starts_with(p)
        } else {
            false
        }
    })
}

fn load_config(path: &str) -> AppConfig {
    let mut interval = DEFAULT_INTERVAL;
    let mut whitelist = FxHashSet::default();
    if let Ok(content) = fs::read_to_string(path) {
        let mut in_wl = false;
        for line in content
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            if line.starts_with("interval:") {
                if let Some(v) = line.split(':').nth(1).and_then(|v| v.trim().parse().ok()) {
                    interval = v;
                }
                in_wl = false;
            } else if line.starts_with("whitelist:") {
                in_wl = true;
                if let Some(v) = line.split(':').nth(1) {
                    parse_whitelist_rules(v, &mut whitelist);
                }
            } else if in_wl {
                parse_whitelist_rules(line, &mut whitelist);
            }
        }
    }
    AppConfig {
        interval,
        whitelist,
    }
}

fn parse_whitelist_rules(line: &str, whitelist: &mut FxHashSet<WhitelistRule>) {
    for pkg in line.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
        if let Some(p) = pkg.strip_suffix(":*") {
            whitelist.insert(WhitelistRule::Prefix(p.to_string()));
        } else {
            whitelist.insert(WhitelistRule::Exact(pkg.to_string()));
        }
    }
}

static TIME_FMT: &[FormatItem<'static>] =
    format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");
fn now_fmt() -> String {
    OffsetDateTime::now_local()
        .unwrap_or_else(|_| OffsetDateTime::now_utc())
        .format(TIME_FMT)
        .unwrap_or_default()
}

struct Logger {
    path: std::path::PathBuf,
    last_write_date: Option<Date>,
}
impl Logger {
    fn new(path: Option<String>) -> Option<Self> {
        path.map(|p| Self {
            path: std::path::PathBuf::from(p),
            last_write_date: None,
        })
    }
    fn open_writer(&mut self) -> Option<BufWriter<File>> {
        let today = OffsetDateTime::now_local()
            .unwrap_or_else(|_| OffsetDateTime::now_utc())
            .date();
        let mut trunc = false;
        if self.last_write_date != Some(today) {
            if let Ok(m) = fs::metadata(&self.path).and_then(|m| m.modified()) {
                if OffsetDateTime::from(m).date() != today {
                    trunc = true;
                }
            } else {
                trunc = true;
            }
            self.last_write_date = Some(today);
        }
        OpenOptions::new()
            .create(true)
            .write(true)
            .append(!trunc)
            .truncate(trunc)
            .open(&self.path)
            .ok()
            .map(BufWriter::new)
    }
    fn write_startup(&mut self) {
        if let Some(mut w) = self.open_writer() {
            let _ = writeln!(
                w,
                "=== 启动时间: {} ===\n⚡ eBPF 进程压制 (双线程 Epoll 版) 已启动 ⚡\n",
                now_fmt()
            );
        }
    }
    fn write_cleanup(&mut self, killed_list: &[String]) {
        if let Some(mut w) = self.open_writer() {
            let _ = writeln!(w, "=== 清理时间: {} ===", now_fmt());
            for pkg in killed_list {
                let _ = writeln!(w, "已清理: {}", pkg);
            }
            let _ = writeln!(w);
        }
    }
}
