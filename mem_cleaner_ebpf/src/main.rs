#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use mem_cleaner_common::ProcessEvent;

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
    // 64位系统调用参数从偏移量16开始。必须明确指定读取类型 <u32>
    let ruid = match unsafe { ctx.read_at::<u32>(16) } {
        Ok(v) => v,
        Err(_) => return Ok(0),
    };

    if ruid < 10000 {
        return Ok(0);
    }

    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

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
