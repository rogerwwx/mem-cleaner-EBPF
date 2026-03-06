#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_get_current_comm,
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
};
use mem_cleaner_common::ProcessEvent;

#[map]
static EVENTS: PerfEventArray<ProcessEvent> = PerfEventArray::new(0);

#[tracepoint]
pub fn sched_process_fork(ctx: TracePointContext) -> u32 {
    // 1. 获取当前进程名（该版本函数无参数，直接返回Result<[u8;16], c_long>）
    let comm = match unsafe { bpf_get_current_comm() } {
        Ok(val) => val,
        Err(_) => return 0,
    };

    // 2. 过滤，只允许 zygote/zygote64（建议加\0匹配内核存储格式）
    if !(comm.starts_with(b"zygote\0") || comm.starts_with(b"zygote64\0")) {
        return 0;
    }

    // 3. 硬编码偏移量读取 child_pid
    let child_pid_offset = 44;
    let child_pid: u32 = unsafe {
        match ctx.read_at(child_pid_offset) {
            Ok(val) => val,
            Err(_) => return 0,
        }
    };

    // 4. 输出到用户态（aya-ebpf的output是安全函数，无需unsafe）
    let event = ProcessEvent {
        pid: child_pid,
        _padding: 0,
    };
    let _ = EVENTS.output(&ctx, &event, 0);

    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
