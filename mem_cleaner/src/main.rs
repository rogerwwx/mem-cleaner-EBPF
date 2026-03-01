use aya::programs::TracePoint;
use aya::Bpf;
use aya::maps::RingBuf;
use mem_cleaner_common::ProcessEvent;

use fxhash::FxHashSet;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use tokio::time::{sleep, Duration};
use tokio::sync::Mutex;

use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::sync::Arc;

use time::macros::format_description;
use time::{format_description::FormatItem, Date, OffsetDateTime};

// --- 常量配置 ---
const OOM_SCORE_THRESHOLD: i32 = 800; 
const INIT_DELAY_SECS: u64 = 3;     // 短延迟：等待 AMS 下发 OOM Score 和改名
const GRACE_PERIOD_SECS: u64 = 60;  // 长延迟：防抖观察期

// --- 结构体与白名单 ---
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum WhitelistRule {
    Exact(String),
    Prefix(String),
}

struct AppConfig {
    whitelist: FxHashSet<WhitelistRule>,
}

// --- 主程序入口 ---
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <config_path> [log_path]", args[0]);
        std::process::exit(1);
    }

    let config_path = &args[1];
    let log_path = if args.len() > 2 { Some(args[2].clone()) } else { None };

    println!("⚡ 正在初始化 eBPF 进程压制器 (Kernel 5.15) ⚡");
    let config = Arc::new(load_config(config_path));
    let mut logger = Logger::new(log_path);
    if let Some(l) = &mut logger { l.write_startup(); }
    let logger = Arc::new(Mutex::new(logger));

    // 1. 动态加载 eBPF 字节码 (这里假设你按之前的命令编译了 ebpf 模块)
    let bpf_bytes = include_bytes!("../../target/bpfel-unknown-none/release/mem_cleaner-ebpf");
    let mut bpf = Bpf::load(bpf_bytes)?;

    // 2. 挂载 Tracepoint (sys_enter_setresuid)
    let program: &mut TracePoint = bpf.program_mut("trace_setresuid").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_setresuid")?;
    println!("✅ eBPF Tracepoint 挂载成功!");

    // 3. 打开 Ring Buffer 监听器
    let mut ring_buf = RingBuf::try_from(bpf.map_mut("EVENTS").unwrap())?;

    // 用于记录正在观察期的 PID，防止重复触发
    let tracking_pids = Arc::new(Mutex::new(FxHashSet::default()));

    println!("🎧 进入极低功耗事件监听模式...");

    // 4. 异步无阻塞事件循环
    loop {
        // 没有进程启动时，这里完全休眠，0 CPU 占用
        let Some(item) = ring_buf.next().await else { continue };
        let event = unsafe { std::ptr::read_unaligned(item.as_ptr() as *const ProcessEvent) };

        let tracking = tracking_pids.clone();
        let cfg = config.clone();
        let log = logger.clone();

        // 为每个新进程派生一个轻量级协程
        tokio::spawn(async move {
            handle_new_process(event.pid, tracking, cfg, log).await;
        });
    }
}

/// 核心逻辑：双重延迟状态机 (防频繁重启耗电)
async fn handle_new_process(
    pid: u32, 
    tracking: Arc<Mutex<FxHashSet<u32>>>, 
    config: Arc<AppConfig>,
    logger: Arc<Mutex<Option<Logger>>>,
) {
    // 查重
    {
        let mut t = tracking.lock().await;
        if t.contains(&pid) { return; }
        t.insert(pid);
    }

    // ==========================================
    // 阶段 1：短延迟等待 AMS 赋值
    // ==========================================
    sleep(Duration::from_secs(INIT_DELAY_SECS)).await;

    // 获取 Cmdline 和 OOM Score
    let cmdline = get_cmdline(pid);
    if cmdline.is_empty() || !cmdline.contains(':') || is_in_whitelist(&cmdline, &config.whitelist) {
        remove_tracking(pid, &tracking).await;
        return; 
    }

    if get_oom_score(pid) < OOM_SCORE_THRESHOLD {
        remove_tracking(pid, &tracking).await;
        return;
    }

    // ==========================================
    // 阶段 2：长延迟观察期
    // ==========================================
    sleep(Duration::from_secs(GRACE_PERIOD_SECS)).await;

    // 终极检查：过了 60 秒依然赖在后台？
    let final_score = get_oom_score(pid);
    if final_score >= OOM_SCORE_THRESHOLD {
        if kill(Pid::from_raw(pid as i32), Signal::SIGKILL).is_ok() {
            // 写入日志
            let mut log_guard = logger.lock().await;
            if let Some(l) = log_guard.as_mut() {
                l.write_cleanup(&[cmdline.clone()]);
            }
        }
    }

    remove_tracking(pid, &tracking).await;
}

// --- 辅助与工具函数 ---

async fn remove_tracking(pid: u32, tracking: &Arc<Mutex<FxHashSet<u32>>>) {
    let mut t = tracking.lock().await;
    t.remove(&pid);
}

fn get_oom_score(pid: u32) -> i32 {
    let path = format!("/proc/{}/oom_score_adj", pid);
    if let Ok(content) = fs::read_to_string(&path) {
        if let Ok(score) = content.trim().parse::<i32>() {
            return score;
        }
    }
    -1000 // 读取失败说明进程已死
}

fn get_cmdline(pid: u32) -> String {
    let path = format!("/proc/{}/cmdline", pid);
    if let Ok(content) = fs::read(&path) {
        if let Some(slice) = content.split(|&c| c == 0).next() {
            return String::from_utf8_lossy(slice).into_owned();
        }
    }
    String::new()
}

fn is_in_whitelist(cmdline: &str, whitelist: &FxHashSet<WhitelistRule>) -> bool {
    if whitelist.contains(&WhitelistRule::Exact(cmdline.to_string())) {
        return true;
    }
    for rule in whitelist {
        if let WhitelistRule::Prefix(prefix) = rule {
            if cmdline.starts_with(prefix) {
                return true;
            }
        }
    }
    false
}

// --- 配置与日志 (保留原样) ---

fn load_config(path: &str) -> AppConfig {
    let mut whitelist: FxHashSet<WhitelistRule> = FxHashSet::default();
    whitelist.insert(WhitelistRule::Exact("com.android.systemui".to_string()));
    whitelist.insert(WhitelistRule::Exact("android".to_string()));
    whitelist.insert(WhitelistRule::Exact("com.android.phone".to_string()));

    if let Ok(content) = fs::read_to_string(path) {
        let mut in_whitelist_mode = false;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }

            if line.starts_with("whitelist:") {
                in_whitelist_mode = true;
                if let Some(val_part) = line.split(':').nth(1) {
                    parse_whitelist_rules(val_part, &mut whitelist);
                }
            } else if in_whitelist_mode {
                parse_whitelist_rules(line, &mut whitelist);
            }
        }
    }

    AppConfig { whitelist }
}

fn parse_whitelist_rules(line: &str, whitelist: &mut FxHashSet<WhitelistRule>) {
    for part in line.split(',') {
        let pkg = part.trim();
        if pkg.is_empty() { continue; }
        if let Some(prefix) = pkg.strip_suffix(":*") {
            whitelist.insert(WhitelistRule::Prefix(prefix.to_string()));
        } else {
            whitelist.insert(WhitelistRule::Exact(pkg.to_string()));
        }
    }
}

static TIME_FMT: &[FormatItem<'static>] = format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");

fn now_fmt() -> String {
    let dt = OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc());
    dt.format(TIME_FMT).unwrap_or_else(|_| "time_err".to_string())
}

struct Logger {
    path: std::path::PathBuf,
    last_write_date: Option<Date>,
}

impl Logger {
    fn new(path: Option<String>) -> Option<Self> {
        path.map(|p| Self { path: std::path::PathBuf::from(p), last_write_date: None })
    }

    fn open_writer(&mut self) -> Option<BufWriter<File>> {
        let now = OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc());
        let today = now.date();
        let mut should_truncate = false;

        if self.last_write_date != Some(today) {
            if let Ok(meta) = fs::metadata(&self.path) {
                if let Ok(mtime) = meta.modified() {
                    let file_date = OffsetDateTime::from(mtime).date();
                    if file_date != today { should_truncate = true; }
                }
            } else { should_truncate = true; }
            self.last_write_date = Some(today);
        }

        let file = OpenOptions::new().create(true).write(true).append(!should_truncate).truncate(should_truncate).open(&self.path).ok()?;
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
            for pkg in killed_list { let _ = writeln!(writer, "已清理: {}", pkg); }
            let _ = writeln!(writer);
        }
    }
}