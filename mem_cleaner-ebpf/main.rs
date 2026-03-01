#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use mem_cleaner_common::ProcessEvent;

// 定义 Ring Buffer (5.15 内核原生支持，性能极高)
// 64KB 足够缓冲上万个瞬间进程启动事件
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
    // sys_enter_setresuid 的第一个参数是 ruid
    let ruid: u32 = unsafe { ctx.arg(0) };

    // 【核心性能优化】: 直接在内核态过滤系统进程！
    // Android App 的 UID 从 10000 开始。小于 10000 的全部是底层系统进程。
    // 直接 return 0，完全不唤醒用户态，0 性能损耗。
    if ruid < 10000 {
        return Ok(0);
    }

    // 获取当前进程的 PID (在内核中，tgid 对应用户态的 pid)
    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // 申请 Ring Buffer 空间并发送事件
    if let Some(mut buf) = EVENTS.reserve::<ProcessEvent>(0) {
        unsafe {
            (*buf.as_mut_ptr()).pid = pid;
            (*buf.as_mut_ptr()).uid = ruid;
        }
        // 提交事件，唤醒用户态 Tokio 任务
        buf.submit(0);
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
