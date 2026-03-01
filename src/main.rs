use fxhash::FxHashSet;
use itoa::Buffer as ItoaBuffer;
use nix::fcntl::{open, openat, OFlag};
use nix::sys::signal::{kill, Signal};
use nix::sys::stat::{fstatat, Mode};
use nix::sys::time::TimeSpec;
use nix::sys::timerfd::{ClockId, Expiration, TimerFd, TimerFlags, TimerSetTimeFlags};
use nix::unistd::Pid;

use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::os::unix::io::{FromRawFd, RawFd};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use time::macros::format_description;
use time::{format_description::FormatItem, Date, OffsetDateTime};

// --- 常量配置 ---
const OOM_SCORE_THRESHOLD: i32 = 800; // 只有大于此值的进程才会被检查
const DEFAULT_INTERVAL: u64 = 60;
const DOZE_CACHE_TTL_SECS: u64 = 30; // Doze 状态缓存时间，避免频繁 fork

// --- 结构体定义 ---
/// 白名单匹配规则：支持完全匹配或前缀匹配
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum WhitelistRule {
    Exact(String),  // 完全匹配
    Prefix(String), // 前缀匹配（对应 xxx:* 格式）
}

struct AppConfig {
    interval: u64,
    whitelist: FxHashSet<WhitelistRule>, // 规则集合
}

/// 扫描资源复用池
struct ScannerResources {
    path_buf: String,    // 复用路径字符串 "/proc/12345/..."
    file_buf: Vec<u8>,   // 复用文件读取 buffer
    cmdline_buf: String, // 复用 cmdline 解析 buffer
}

impl ScannerResources {
    fn new() -> Self {
        Self {
            path_buf: String::with_capacity(64),
            file_buf: Vec::with_capacity(128),
            cmdline_buf: String::with_capacity(128),
        }
    }
}

/// 智能日志管理器
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
                    let mtime_dt = OffsetDateTime::from(mtime);
                    let file_date = mtime_dt.date();
                    if file_date != today {
                        should_truncate = true;
                    }
                } else {
                    should_truncate = false;
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
            let _ = writeln!(writer, "⚡ 进程压制已启动 ⚡");
            let _ = writeln!(writer);
        }
    }

    fn write_cleanup(&mut self, killed_list: &[String]) {
        if killed_list.is_empty() {
            return;
        }
        if let Some(mut writer) = self.open_writer() {
            let _ = writeln!(writer, "=== 清理时间: {} ===", now_fmt());
            for pkg in killed_list {
                let _ = writeln!(writer, "已清理: {}", pkg);
            }
            let _ = writeln!(writer);
        }
    }
}

// --- Doze 缓存 (减少 fork 开销) ---
struct DozeCache {
    last_checked: Option<Instant>,
    is_deep: bool,
    ttl: Duration,
}

impl DozeCache {
    fn new(ttl: Duration) -> Self {
        Self {
            last_checked: None,
            is_deep: false,
            ttl,
        }
    }

    fn is_deep_doze_cached(&mut self) -> bool {
        let now = Instant::now();
        if let Some(t) = self.last_checked {
            if now.duration_since(t) < self.ttl {
                return self.is_deep;
            }
        }

        let state = is_device_in_deep_doze();
        self.last_checked = Some(now);
        self.is_deep = state;
        state
    }
}

fn main() {
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

    println!("Starting Daemon...");
    let config = load_config(config_path);
    println!("Interval: {}s", config.interval);

    let mut logger = Logger::new(log_path);
    if let Some(l) = &mut logger {
        l.write_startup();
    }

    // TimerFD 保留（作为兜底与周期性任务）
    let timer = TimerFd::new(ClockId::CLOCK_BOOTTIME, TimerFlags::empty())
        .expect("Failed to create timerfd");
    let interval_spec = TimeSpec::new(config.interval as i64, 0);
    timer
        .set(
            Expiration::Interval(interval_spec),
            TimerSetTimeFlags::empty(),
        )
        .expect("Failed to set timer");

    // 预打开 /proc 目录 fd
    let proc_fd = match open(
        Path::new("/proc"),
        OFlag::O_DIRECTORY | OFlag::O_RDONLY,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("Failed to open /proc: {}", e);
            std::process::exit(1);
        }
    };

    let mut doze_cache = DozeCache::new(Duration::from_secs(DOZE_CACHE_TTL_SECS));
    let mut resources = ScannerResources::new();

    loop {
        let _ = timer.wait();

        if doze_cache.is_deep_doze_cached() {
            continue;
        }

        perform_cleanup(&config.whitelist, &mut logger, &mut resources, proc_fd);
    }
}

/// 检查进程是否在白名单中（支持完全匹配和前缀匹配）
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

/// 核心清理逻辑：严格遵循“漏斗模型”进行极致性能过滤
fn perform_cleanup(
    whitelist: &FxHashSet<WhitelistRule>,
    logger: &mut Option<Logger>,
    res: &mut ScannerResources,
    proc_fd: RawFd,
) {
    let proc_dir = match fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return,
    };

    let mut killed_list: Vec<String> = Vec::new();
    let mut itoa_buf = ItoaBuffer::new();

    for entry in proc_dir {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let file_name = entry.file_name();
        let file_name_bytes = file_name.as_encoded_bytes();

        // 只处理纯数字的 PID 目录
        if file_name_bytes.is_empty() || !file_name_bytes.iter().all(|b| b.is_ascii_digit()) {
            continue;
        }

        let pid_str = unsafe { std::str::from_utf8_unchecked(file_name_bytes) };
        let pid: i32 = match pid_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        // 使用 itoa 将 pid 转为字符串（零分配）
        let pid_s = itoa_buf.format(pid);

        // ==========================================
        // 漏斗第 1 层：查 UID (最轻量，仅 1 次 fstatat syscall)
        // 过滤掉 30%~40% 的底层系统进程 (UID < 10000)
        // ==========================================
        let pid_path = Path::new(pid_s);
        match fstatat(Some(proc_fd), pid_path, nix::fcntl::AtFlags::empty()) {
            Ok(stat) => {
                if stat.st_uid < 10000 {
                    continue; // 核心系统进程，直接跳过
                }
            }
            Err(_) => continue,
        }

        // ==========================================
        // 漏斗第 2 层：查 oom_score_adj (较轻量，3 次 syscall + 简单解析)
        // 过滤掉前台和活跃 App (score < 800)
        // ==========================================
        res.path_buf.clear();
        res.path_buf.push_str(pid_s);
        res.path_buf.push_str("/oom_score_adj");

        let score = {
            let p_oom = Path::new(&res.path_buf);
            match openat(Some(proc_fd), p_oom, OFlag::O_RDONLY, Mode::empty()) {
                Ok(fd) => {
                    let mut f = unsafe { File::from_raw_fd(fd) };
                    res.file_buf.clear();
                    let _ = f.read_to_end(&mut res.file_buf);
                    let s = std::str::from_utf8(&res.file_buf).ok().map(|s| s.trim());
                    s.and_then(|s| s.parse::<i32>().ok())
                }
                Err(_) => None,
            }
        };

        if let Some(s) = score {
            if s < OOM_SCORE_THRESHOLD {
                continue; // 活跃进程，跳过
            }
        } else {
            continue;
        }

        // ==========================================
        // 漏斗第 3 层：查 cmdline 并匹配白名单 (最重，涉及字符串操作)
        // 只有高危驻留后台 App 才会走到这一步
        // ==========================================
        res.path_buf.clear();
        res.path_buf.push_str(pid_s);
        res.path_buf.push_str("/cmdline");

        let cmd_ok = match openat(
            Some(proc_fd),
            Path::new(&res.path_buf),
            OFlag::O_RDONLY,
            Mode::empty(),
        ) {
            Ok(fd) => {
                let mut f = unsafe { File::from_raw_fd(fd) };
                res.file_buf.clear();
                if f.read_to_end(&mut res.file_buf).is_err() {
                    false
                } else {
                    let slice = res.file_buf.split(|&c| c == 0).next().unwrap_or(&[]);
                    res.cmdline_buf.clear();
                    res.cmdline_buf.push_str(&String::from_utf8_lossy(slice));
                    !res.cmdline_buf.is_empty()
                }
            }
            Err(_) => false,
        };

        if !cmd_ok {
            continue;
        }

        let cmdline = &res.cmdline_buf;

        if cmdline.is_empty() {
            continue;
        }

        // 白名单过滤
        if is_in_whitelist(cmdline, whitelist) {
            continue;
        }

        // 仅杀带有 ':' 的进程 (通常是 App 的后台服务进程，如 com.xxx.app:push)
        if !cmdline.contains(':') {
            continue;
        }

        // 击杀目标进程
        if kill(Pid::from_raw(pid), Signal::SIGKILL).is_ok() {
            killed_list.push(cmdline.clone());
        }
    }

    if !killed_list.is_empty() {
        if let Some(l) = logger {
            l.write_cleanup(&killed_list);
        }
    }
}

fn is_device_in_deep_doze() -> bool {
    if let Ok(output) = Command::new("cmd")
        .args(&["deviceidle", "get", "deep"])
        .output()
    {
        let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
        return s == "IDLE";
    }
    false
}

// --- 配置加载与时间 ---

fn load_config(path: &str) -> AppConfig {
    let mut interval = DEFAULT_INTERVAL;
    let mut whitelist: FxHashSet<WhitelistRule> = FxHashSet::default();

    // 内置默认白名单（完全匹配）
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

/// 解析白名单规则（支持 xxx:* 前缀匹配 和 xxx 完全匹配）
fn parse_whitelist_rules(line: &str, whitelist: &mut FxHashSet<WhitelistRule>) {
    for part in line.split(',') {
        let pkg = part.trim();
        if pkg.is_empty() {
            continue;
        }

        if let Some(prefix) = pkg.strip_suffix(":*") {
            if prefix.contains(':') || !prefix.is_empty() {
                whitelist.insert(WhitelistRule::Prefix(prefix.to_string()));
            } else {
                whitelist.insert(WhitelistRule::Exact(pkg.to_string()));
            }
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
