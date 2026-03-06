#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
};
use mem_cleaner_common::ProcessEvent;

#[map]
static EVENTS: PerfEventArray<ProcessEvent> = PerfEventArray::new(0);

#[tracepoint]
pub fn sched_process_fork(ctx: TracePointContext) -> u32 {
    // Linux 64-bit (ARM64) sched_process_fork 布局通常如下：
    // common_fields (8 bytes)
    // parent_comm   (16 bytes)
    // parent_pid    (4 bytes)
    // child_comm    (16 bytes)
    // child_pid     (4 bytes) <--- 我们要抓这个
    //
    // Offset = 8 + 16 + 4 + 16 = 44 bytes
    let child_pid_offset = 44;

    // 读取子进程 PID
    let child_pid: u32 = unsafe {
        match ctx.read_at(child_pid_offset) {
            Ok(val) => val,
            Err(_) => return 0,
        }
    };

    // 发送事件给用户态
    let event = ProcessEvent {
        pid: child_pid,
        _padding: 0,
    };

    EVENTS.output(&ctx, &event, 0);

    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
