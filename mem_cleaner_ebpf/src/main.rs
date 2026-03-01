#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
};
use mem_cleaner_common::ProcessEvent;

// 使用 PerfEventArray 替代 RingBuf，完美兼容异步 Tokio
#[map]
static EVENTS: PerfEventArray<ProcessEvent> = PerfEventArray::new(0);

#[tracepoint]
pub fn trace_setresuid(ctx: TracePointContext) -> u32 {
    match try_trace_setresuid(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_trace_setresuid(ctx: TracePointContext) -> Result<u32, u32> {
    let ruid = match unsafe { ctx.read_at::<u32>(16) } {
        Ok(v) => v,
        Err(_) => return Ok(0),
    };

    if ruid < 10000 {
        return Ok(0);
    }

    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let event = ProcessEvent { pid, uid: ruid };

    // 一行代码直接输出到用户态，无需手动 reserve 和 submit
    EVENTS.output(&ctx, &event, 0);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
