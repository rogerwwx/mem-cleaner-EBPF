#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use mem_cleaner-common::ProcessEvent;

// 定义 Ring Buffer (64KB 足够缓冲大量瞬间启动事件)
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

#[tracepoint]
pub fn trace_setresuid(ctx: TracePointContext) -> u32 {
    match try_trace_setresuid(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_trace_setresuid(ctx: TracePointContext) -> Result<u32, u32> {
    // 【核心修复】: Tracepoint 没有 arg() 方法。
    // 在 64 位系统的 sys_enter Tracepoint 内存布局中：
    // 0~7 字节: 通用字段 (trace_entry)
    // 8~11 字节: syscall 编号
    // 12~15 字节: 内存对齐填充
    // 16~23 字节: 系统调用的第一个参数 (在这里即 ruid)
    let ruid: u32 = match unsafe { ctx.read_at(16) } {
        Ok(v) => v,
        Err(_) => return Ok(0), // 读取失败直接放过
    };

    // 绝杀优化：直接在内核态丢弃底层系统进程 (UID < 10000)
    // 完全不唤醒用户态，0 开销！
    if ruid < 10000 {
        return Ok(0);
    }

    // 获取当前进程 PID
    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // 申请 Ring Buffer 空间并发送事件
    if let Some(mut buf) = EVENTS.reserve::<ProcessEvent>(0) {
        unsafe {
            (*buf.as_mut_ptr()).pid = pid;
            (*buf.as_mut_ptr()).uid = ruid;
        }
        buf.submit(0);
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
