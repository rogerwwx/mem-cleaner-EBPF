use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::Bpf;
use bytes::BytesMut;
use mem_cleaner_common::ProcessEvent;

use fxhash::FxHashSet;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};

use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::os::unix::fs::MetadataExt;
use std::process::Command;
use std::sync::Arc;

use time::macros::format_description;
use time::{format_description::FormatItem, Date, OffsetDateTime};

const OOM_SCORE_THRESHOLD: i32 = 800;
const INIT_DELAY_SECS: u64 = 2;
const DEFAULT_INTERVAL: u64 = 30;
const MIN_APP_UID: u32 = 10000;
const DOZE_PAUSE_SECS: u64 = 60;
const DOZE_CHECK_CMD: &str = "deviceidle";
const DOZE_CHECK_ARGS: &[&str] = &["get", "deep"];

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <config_path>[log_path]", args[0]);
        std::process::exit(1);
    }

    let config_path = &args[1];
    let log_path = if args.len() > 2 {
        Some(args[2].clone())
    } else {
        None
    };

    println!("⚡ 初始化 Android 进程压制器 (内核 UID0 过滤版) ⚡");

    let config = Arc::new(load_config(config_path));
    let mut logger = Logger::new(log_path);
    if let Some(l) = &mut logger {
        l.write_startup();
    }
    let logger = Arc::new(Mutex::new(logger));

    let monitoring_pids = Arc::new(Mutex::new(FxHashSet::default()));

    {
        let mon_pids = monitoring_pids.clone();
        let mon_cfg = config.clone();
        let mon_log = logger.clone();
        tokio::spawn(async move {
            start_monitor_loop(mon_pids, mon_cfg, mon_log).await;
        });
    }

    println!("📦 加载 eBPF 模块...");
    let mut bpf = Bpf::load(&BPF_BYTES.0)?;

    let program: &mut TracePoint = bpf.program_mut("sched_process_fork").unwrap().try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_fork")?;
    println!("✅ eBPF 挂载成功: 完美拦截 Zygote 孵化");

    let mut perf_array = AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;

    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;
        let pids_guard = monitoring_pids.clone();
        let cfg = config.clone();

        tokio::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();
            loop {
                let events = match buf.read_events(&mut buffers).await {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                for i in 0..events.read {
                    let ptr = buffers[i].as_ptr() as *const ProcessEvent;
                    let event = unsafe { std::ptr::read_unaligned(ptr) };
                    let t = pids_guard.clone();
                    let c = cfg.clone();
                    tokio::spawn(async move {
                        handle_fork_event(event.pid, t, c).await;
                    });
                }
            }
        });
    }

    loop {
        sleep(Duration::from_secs(3600)).await;
    }
}

async fn handle_fork_event(
    pid: u32,
    monitoring_pids: Arc<Mutex<FxHashSet<u32>>>,
    config: Arc<AppConfig>,
) {
    // 1. 等待 Zygote 特化为具体 App
    sleep(Duration::from_secs(INIT_DELAY_SECS)).await;

    // 2. 第一层系统免疫：不是 App (UID < 10000) 绝对不碰
    match get_process_uid(pid) {
        Some(uid) if uid < MIN_APP_UID => return,
        None => return,
        _ => {}
    }

    let cmdline = get_cmdline(pid);

    // 3. 保护主进程 (无冒号)、保护残余 zygote、过滤白名单
    if cmdline.is_empty()
        || !cmdline.contains(':')
        || cmdline.contains("zygote")
        || is_in_whitelist(&cmdline, &config.whitelist)
    {
        return;
    }

    // 加入监控，万无一失
    let mut pids = monitoring_pids.lock().await;
    pids.insert(pid);
}

async fn start_monitor_loop(
    monitoring_pids: Arc<Mutex<FxHashSet<u32>>>,
    config: Arc<AppConfig>,
    logger: Arc<Mutex<Option<Logger>>>,
) {
    loop {
        if is_in_deep_doze() {
            sleep(Duration::from_secs(DOZE_PAUSE_SECS)).await;
            continue;
        }

        sleep(Duration::from_secs(config.interval)).await;

        let pids_to_check: Vec<u32> = {
            let pids = monitoring_pids.lock().await;
            pids.iter().cloned().collect()
        };

        if pids_to_check.is_empty() {
            continue;
        }

        let mut pids_to_remove = Vec::new();
        let mut killed_in_this_round = Vec::new();

        for pid in pids_to_check {
            // 杀前复核 UID，彻底掐死 PID 复用导致杀系统进程的可能
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
                    killed_in_this_round.push(format!("PID:{} | OOM:{} | {}", pid, score, cmdline));
                    pids_to_remove.push(pid);
                } else {
                    pids_to_remove.push(pid);
                }
            }
        }

        if !killed_in_this_round.is_empty() {
            let mut log_guard = logger.lock().await;
            if let Some(l) = log_guard.as_mut() {
                l.write_cleanup(&killed_in_this_round);
            }
        }

        if !pids_to_remove.is_empty() {
            let mut pids = monitoring_pids.lock().await;
            for pid in pids_to_remove {
                pids.remove(&pid);
            }
        }
    }
}

// ================== 辅助函数 ==================
fn get_process_uid(pid: u32) -> Option<u32> {
    fs::metadata(format!("/proc/{}", pid)).ok().map(|m| m.uid())
}

fn get_oom_score(pid: u32) -> i32 {
    fs::read_to_string(format!("/proc/{}/oom_score_adj"))
        .ok()
        .and_then(|c| c.trim().parse::<i32>().ok())
        .unwrap_or(-1000)
}

fn get_cmdline(pid: u32) -> String {
    fs::read(format!("/proc/{}/cmdline"))
        .ok()
        .and_then(|c| {
            c.split(|&ch| ch == 0)
                .next()
                .map(|s| String::from_utf8_lossy(s).into_owned())
        })
        .unwrap_or_default()
}

fn is_in_deep_doze() -> bool {
    Command::new("cmd")
        .arg(DOZE_CHECK_CMD)
        .args(DOZE_CHECK_ARGS)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "IDLE")
        .unwrap_or(false)
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
                "=== 启动时间: {} ===\n⚡ eBPF 进程压制已启动 ⚡\n",
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
