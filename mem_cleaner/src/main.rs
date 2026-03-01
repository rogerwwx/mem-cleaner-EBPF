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
// 必须引入这个 trait 才能获取 uid
use std::os::unix::fs::MetadataExt;
use std::process::Command;
use std::sync::Arc;

use time::macros::format_description;
use time::{format_description::FormatItem, Date, OffsetDateTime};

// 原有的常量
const OOM_SCORE_THRESHOLD: i32 = 800;
const INIT_DELAY_SECS: u64 = 1;
const DEFAULT_INTERVAL: u64 = 60;
const MIN_APP_UID: u32 = 10000;

// === 新增 Doze 相关配置 ===
// 当检测到 Doze 模式时，暂停轮询的时长 (秒)，建议设长一点，比如 5 分钟
const DOZE_PAUSE_SECS: u64 = 300;

// Doze 状态检测命令 (Android 6.0+ 支持)
// 使用 cmd 相比 dumpsys 更轻量
const DOZE_CHECK_CMD: &str = "deviceidle";
const DOZE_CHECK_ARGS: &[&str] = &["get", "deep"];

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

    println!("⚡ 正在初始化 eBPF 进程压制器 (Kernel 5.15) ⚡");

    let config = Arc::new(load_config(config_path));
    println!("⏱️  设置全局轮询扫描周期: {} 秒", config.interval);

    let mut logger = Logger::new(log_path);
    if let Some(l) = &mut logger {
        l.write_startup();
    }
    let logger = Arc::new(Mutex::new(logger));

    let monitoring_pids = Arc::new(Mutex::new(FxHashSet::default()));

    // 启动全局轮询监控任务
    {
        let mon_pids = monitoring_pids.clone();
        let mon_cfg = config.clone();
        let mon_log = logger.clone();
        tokio::spawn(async move {
            start_monitor_loop(mon_pids, mon_cfg, mon_log).await;
        });
    }

    let bpf_bytes = include_bytes!("../../target/bpfel-unknown-none/release/mem_cleaner_ebpf");
    let mut bpf = Bpf::load(bpf_bytes)?;

    // 依然使用 sched_process_exec，抓取新启动的二进制程序
    let program: &mut TracePoint = bpf.program_mut("sched_process_exec").unwrap().try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_exec")?;
    println!("✅ eBPF Tracepoint 挂载成功!");

    let mut perf_array = AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;

    println!("🎧 进入极低功耗事件监听模式 (UID过滤已开启)...");

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
                        register_new_process(event.pid, t, c).await;
                    });
                }
            }
        });
    }

    loop {
        sleep(Duration::from_secs(3600)).await;
    }
}

fn is_in_deep_doze() -> bool {
    // 执行: cmd deviceidle get deep
    // 输出: "IDLE" (休眠) 或 "ACTIVE" (活跃) / "INACTIVE" (未激活)
    if let Ok(output) = Command::new("cmd") // 注意：必须在 root 下运行，eBPF 本身就要求 root
        .arg(DOZE_CHECK_CMD)
        .args(DOZE_CHECK_ARGS)
        .output()
    {
        let output_str = String::from_utf8_lossy(&output.stdout);
        // 只要输出包含 IDLE 且不包含 INACTIVE/ACTIVE 即视为休眠
        return output_str.trim() == "IDLE";
    }
    // 如果命令执行失败，默认认为设备是醒着的，继续监控，防止漏杀
    false
}

async fn register_new_process(
    pid: u32,
    monitoring_pids: Arc<Mutex<FxHashSet<u32>>>,
    config: Arc<AppConfig>,
) {
    sleep(Duration::from_secs(INIT_DELAY_SECS)).await;

    // 1. UID 过滤：这是最重要的安全检查！
    // 如果获取不到 UID (进程已死) 或者 UID < 10000 (系统进程)，直接忽略
    match get_process_uid(pid) {
        Some(uid) if uid < MIN_APP_UID => return, // 忽略系统进程
        None => return,                           // 进程不存在
        _ => {}                                   // 用户进程，继续
    }

    // 2. Cmdline 检查和白名单
    let cmdline = get_cmdline(pid);
    if cmdline.is_empty() || !cmdline.contains(':') || is_in_whitelist(&cmdline, &config.whitelist)
    {
        return;
    }

    // 3. 加入监控列表
    let mut pids = monitoring_pids.lock().await;
    pids.insert(pid);
}

/// 监控阶段：周期性轮询所有嫌疑进程
async fn start_monitor_loop(
    monitoring_pids: Arc<Mutex<FxHashSet<u32>>>,
    config: Arc<AppConfig>,
    logger: Arc<Mutex<Option<Logger>>>,
) {
    loop {
        // --- 1. Doze 状态检测 ---
        if is_in_deep_doze() {
            // 如果处于 Doze 模式，打印日志（可选）并进入长睡眠
            // 此时不进行任何 PID 检查，彻底让出 CPU
            // println!("💤 设备处于 Doze 模式，暂停监控 {} 秒...", DOZE_PAUSE_SECS);
            sleep(Duration::from_secs(DOZE_PAUSE_SECS)).await;
            continue; // 跳过本次循环，直接进入下一轮检测
        }

        // --- 2. 正常的轮询间隔 ---
        // 设备处于活跃状态，按配置文件中的间隔等待 (默认 60s)
        sleep(Duration::from_secs(config.interval)).await;

        // --- 3. 执行核心监控逻辑 (保持不变) ---
        let pids_to_check: Vec<u32> = {
            let pids = monitoring_pids.lock().await;
            pids.iter().cloned().collect()
        };

        if pids_to_check.is_empty() {
            continue;
        }

        let mut pids_to_remove = Vec::new();

        for pid in pids_to_check {
            // 检查进程存活
            let cmdline = get_cmdline(pid);
            if cmdline.is_empty() {
                pids_to_remove.push(pid);
                continue;
            }

            // 检查 OOM 分数
            let score = get_oom_score(pid);

            // 杀掉后台进程
            if score >= OOM_SCORE_THRESHOLD {
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

        // 移除已处理的 PID
        if !pids_to_remove.is_empty() {
            let mut pids = monitoring_pids.lock().await;
            for pid in pids_to_remove {
                pids.remove(&pid);
            }
        }
    }
}

fn load_config(path: &str) -> AppConfig {
    let mut interval = DEFAULT_INTERVAL;
    let mut whitelist: FxHashSet<WhitelistRule> = FxHashSet::default();

    whitelist.insert(WhitelistRule::Exact("com.android.systemui".to_string()));
    whitelist.insert(WhitelistRule::Exact("android".to_string()));
    whitelist.insert(WhitelistRule::Exact("com.android.phone".to_string()));

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
