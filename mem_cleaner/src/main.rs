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

// === 配置常量 ===
const OOM_SCORE_THRESHOLD: i32 = 800; // OOM 分数阈值 (>=800 视为后台缓存进程)
const INIT_DELAY_SECS: u64 = 2; // 等待 Zygote 变身为 App 的时间 (设为 2 秒更稳妥)
const DEFAULT_INTERVAL: u64 = 30; // 默认轮询检查间隔
const MIN_APP_UID: u32 = 10000; // Android App 的最小 UID
const DOZE_PAUSE_SECS: u64 = 60; // Doze 模式下暂停监控的时长

// Doze 检测命令
const DOZE_CHECK_CMD: &str = "deviceidle";
const DOZE_CHECK_ARGS: &[&str] = &["get", "deep"];

// 强制 ARM64 8字节对齐，防止 load 崩溃 (核心修复)
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
        eprintln!("Usage: {} <config_path> [log_path]", args[0]);
        std::process::exit(1);
    }

    let config_path = &args[1];
    let log_path = if args.len() > 2 {
        Some(args[2].clone())
    } else {
        None
    };

    println!("⚡ 初始化 Android 进程压制器 (Fork 监听版) ⚡");

    let config = Arc::new(load_config(config_path));
    println!(
        "⏱️  监控间隔: {}s | 白名单规则数: {}",
        config.interval,
        config.whitelist.len()
    );

    let mut logger = Logger::new(log_path);
    if let Some(l) = &mut logger {
        l.write_startup();
    }
    let logger = Arc::new(Mutex::new(logger));

    // 监控集合：存放所有待查杀的 App PID
    let monitoring_pids = Arc::new(Mutex::new(FxHashSet::default()));

    // --- 启动后台轮询监控 (Consumer) ---
    {
        let mon_pids = monitoring_pids.clone();
        let mon_cfg = config.clone();
        let mon_log = logger.clone();
        tokio::spawn(async move {
            start_monitor_loop(mon_pids, mon_cfg, mon_log).await;
        });
    }

    // --- 加载 eBPF ---
    println!("📦 加载 eBPF 模块 (大小: {} bytes)...", BPF_BYTES.0.len());
    let mut bpf = Bpf::load(&BPF_BYTES.0)?;

    // 挂载 sched_process_fork
    let program: &mut TracePoint = bpf.program_mut("sched_process_fork").unwrap().try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_fork")?;
    println!("✅ eBPF 挂载成功: 监听 Zygote Fork 事件");

    let mut perf_array = AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;

    println!("🎧 服务已就绪，等待 App 启动...");

    // --- 启动事件监听 (Producer) ---
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

                    // 每一个 Fork 事件都启动一个异步任务去处理
                    tokio::spawn(async move {
                        handle_fork_event(event.pid, t, c).await;
                    });
                }
            }
        });
    }

    // 主线程保活
    loop {
        sleep(Duration::from_secs(3600)).await;
    }
}

// === 处理 Fork 事件 ===
async fn handle_fork_event(
    pid: u32,
    monitoring_pids: Arc<Mutex<FxHashSet<u32>>>,
    config: Arc<AppConfig>,
) {
    // 关键步骤：等待 Zygote 进程特化 (Specialize)
    // 刚 fork 出来的瞬间，PID 的名字叫 "zygote"，UID 是 0
    // 我们睡 2 秒，等 Android 系统把它变成 "com.example.app"，UID 变成 10xxx
    sleep(Duration::from_secs(INIT_DELAY_SECS)).await;

    // 1. 检查 UID：如果是系统进程 (<10000)，直接忽略
    match get_process_uid(pid) {
        Some(uid) if uid < MIN_APP_UID => return,
        None => return, // 进程可能启动失败直接退出了
        _ => {}
    }

    // 2. 获取包名 (cmdline)
    let cmdline = get_cmdline(pid);
    if cmdline.is_empty() {
        return;
    }

    // 3. 检查白名单
    if is_in_whitelist(&cmdline, &config.whitelist) {
        // println!("🛡️ 白名单应用: {} (PID: {})", cmdline, pid);
        return;
    }

    // 4. 加入监控列表
    // println!("➕ 发现目标应用: {} (PID: {}) - 加入监控", cmdline, pid);
    let mut pids = monitoring_pids.lock().await;
    pids.insert(pid);
}

// === 后台监控循环 ===
async fn start_monitor_loop(
    monitoring_pids: Arc<Mutex<FxHashSet<u32>>>,
    config: Arc<AppConfig>,
    logger: Arc<Mutex<Option<Logger>>>,
) {
    loop {
        // 1. 检测 Doze 模式
        if is_in_deep_doze() {
            // println!("💤 Doze 模式生效，暂停监控...");
            sleep(Duration::from_secs(DOZE_PAUSE_SECS)).await;
            continue;
        }

        // 2. 常规等待
        sleep(Duration::from_secs(config.interval)).await;

        // 3. 检查监控列表
        let pids_to_check: Vec<u32> = {
            let pids = monitoring_pids.lock().await;
            pids.iter().cloned().collect()
        };

        if pids_to_check.is_empty() {
            continue;
        }

        let mut pids_to_remove = Vec::new();

        for pid in pids_to_check {
            // 存活检查
            let cmdline = get_cmdline(pid);
            if cmdline.is_empty() {
                pids_to_remove.push(pid); // 进程已死
                continue;
            }

            // OOM 检查
            let score = get_oom_score(pid);

            // 只有当分数 >= 800 (进入 Cached/后台状态) 时才杀
            if score >= OOM_SCORE_THRESHOLD {
                println!(
                    "🔪 查杀后台进程: {} | OOM: {} | PID: {}",
                    cmdline, score, pid
                );

                if kill(Pid::from_raw(pid as i32), Signal::SIGKILL).is_ok() {
                    let mut log_guard = logger.lock().await;
                    if let Some(l) = log_guard.as_mut() {
                        l.write_cleanup(&[format!("PID:{} | OOM:{} | {}", pid, score, cmdline)]);
                    }
                    pids_to_remove.push(pid);
                } else {
                    pids_to_remove.push(pid);
                }
            }
        }

        // 清理死掉的进程
        if !pids_to_remove.is_empty() {
            let mut pids = monitoring_pids.lock().await;
            for pid in pids_to_remove {
                pids.remove(&pid);
            }
        }
    }
}

// === 辅助函数 ===

fn get_process_uid(pid: u32) -> Option<u32> {
    let path = format!("/proc/{}", pid);
    fs::metadata(path).ok().map(|m| m.uid())
}

fn get_oom_score(pid: u32) -> i32 {
    let path = format!("/proc/{}/oom_score_adj", pid);
    if let Ok(content) = fs::read_to_string(&path) {
        if let Ok(score) = content.trim().parse::<i32>() {
            return score;
        }
    }
    -1000
}

fn get_cmdline(pid: u32) -> String {
    let path = format!("/proc/{}/cmdline", pid);
    if let Ok(content) = fs::read(&path) {
        // Android cmdline 通常以 \0 分隔，我们只取第一段作为包名
        if let Some(slice) = content.split(|&c| c == 0).next() {
            return String::from_utf8_lossy(slice).into_owned();
        }
    }
    String::new()
}

fn is_in_deep_doze() -> bool {
    if let Ok(output) = Command::new("cmd")
        .arg(DOZE_CHECK_CMD)
        .args(DOZE_CHECK_ARGS)
        .output()
    {
        let output_str = String::from_utf8_lossy(&output.stdout);
        return output_str.trim() == "IDLE";
    }
    false
}

fn is_in_whitelist(cmdline: &str, whitelist: &FxHashSet<WhitelistRule>) -> bool {
    // 1. 精确匹配
    if whitelist.contains(&WhitelistRule::Exact(cmdline.to_string())) {
        return true;
    }
    // 2. 前缀匹配
    for rule in whitelist {
        if let WhitelistRule::Prefix(prefix) = rule {
            if cmdline.starts_with(prefix) {
                return true;
            }
        }
    }
    false
}

fn load_config(path: &str) -> AppConfig {
    let mut interval = DEFAULT_INTERVAL;
    let mut whitelist: FxHashSet<WhitelistRule> = FxHashSet::default();

    if let Ok(content) = fs::read_to_string(path) {
        let mut in_whitelist_mode = false;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if line.starts_with("interval:") {
                if let Some(val_part) = line.split(':').nth(1) {
                    if let Ok(val) = val_part.trim().parse::<u64>() {
                        interval = val;
                    }
                }
                in_whitelist_mode = false;
            } else if line.starts_with("whitelist:") {
                in_whitelist_mode = true;
                if let Some(val_part) = line.split(':').nth(1) {
                    parse_whitelist_rules(val_part, &mut whitelist);
                }
            } else if in_whitelist_mode {
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
    for part in line.split(',') {
        let pkg = part.trim();
        if pkg.is_empty() {
            continue;
        }
        if let Some(prefix) = pkg.strip_suffix(":*") {
            whitelist.insert(WhitelistRule::Prefix(prefix.to_string()));
        } else {
            whitelist.insert(WhitelistRule::Exact(pkg.to_string()));
        }
    }
}

// --- 日志模块 (保持简洁) ---
static TIME_FMT: &[FormatItem<'static>] =
    format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");

fn now_fmt() -> String {
    let dt = OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc());
    dt.format(TIME_FMT)
        .unwrap_or_else(|_| "time_err".to_string())
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
        let now = OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc());
        let today = now.date();
        let mut should_truncate = false;

        if self.last_write_date != Some(today) {
            if let Ok(meta) = fs::metadata(&self.path) {
                if let Ok(mtime) = meta.modified() {
                    let file_date = OffsetDateTime::from(mtime).date();
                    if file_date != today {
                        should_truncate = true;
                    }
                }
            } else {
                should_truncate = true;
            }
            self.last_write_date = Some(today);
        }

        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .append(!should_truncate)
            .truncate(should_truncate)
            .open(&self.path)
            .ok()?;
        Some(BufWriter::new(file))
    }

    fn write_startup(&mut self) {
        if let Some(mut writer) = self.open_writer() {
            let _ = writeln!(writer, "=== 启动时间: {} ===", now_fmt());
            let _ = writeln!(writer, "⚡ eBPF 进程压制已启动 ⚡\n");
        }
    }

    fn write_cleanup(&mut self, killed_list: &[String]) {
        if let Some(mut writer) = self.open_writer() {
            let _ = writeln!(writer, "=== 清理时间: {} ===", now_fmt());
            for pkg in killed_list {
                let _ = writeln!(writer, "已清理: {}", pkg);
            }
            let _ = writeln!(writer);
        }
    }
}
