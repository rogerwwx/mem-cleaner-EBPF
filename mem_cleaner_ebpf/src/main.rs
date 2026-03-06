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

#[repr(C)]
struct ForkEvent {
    child_pid: u32,
}

#[tracepoint]
pub fn sched_process_fork(ctx: TracePointContext) -> u32 {
    // 1. 获取触发 fork 的父进程 UID
    let uid = (aya_ebpf::helpers::bpf_get_current_uid_gid() & 0xFFFFFFFF) as u32;

    // 2. 只拦截 Root (UID = 0) 触发的事件
    if uid == 0 {
        let ev: ForkEvent = unsafe {
            match ctx.read_at(44) {
                Ok(val) => val,
                Err(_) => return 0,
            }
        };

        // 发送给用户态
        let event = ProcessEvent {
            pid: ev.child_pid,
            _padding: 0,
        };
        EVENTS.output(&ctx, &event, 0);
    }

    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
