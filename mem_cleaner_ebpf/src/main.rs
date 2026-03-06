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

const TASK_COMM_LEN: usize = 16;

#[tracepoint]
pub fn sched_process_fork(ctx: TracePointContext) -> u32 {
    // 1. 获取当前进程名
    let mut comm = [0u8; TASK_COMM_LEN];
    let ret = unsafe { bpf_get_current_comm(comm.as_mut_ptr(), TASK_COMM_LEN as u32) };
    if ret != 0 {
        return 0;
    }

    // 2. 过滤，只允许 zygote/zygote64
    if !(comm.starts_with(b"zygote") || comm.starts_with(b"zygote64")) {
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

    // 4. 输出到用户态
    let event = ProcessEvent {
        pid: child_pid,
        _padding: 0,
    };
    unsafe {
        EVENTS.output(&ctx, &event, 0);
    }

    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
