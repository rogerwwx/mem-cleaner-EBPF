#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid},
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
};
use mem_cleaner_common::ProcessEvent;

#[map]
static EVENTS: PerfEventArray<ProcessEvent> = PerfEventArray::new(0);

#[tracepoint]
pub fn sched_process_fork(ctx: TracePointContext) -> u32 {
    // 1. 获取触发 fork 的父进程 UID
    let uid = (bpf_get_current_uid_gid() & 0xFFFFFFFF) as u32;

    // 【第一道锁】：必须是 Root 触发 (过滤掉 99.9% 的 App 内部线程)
    if uid == 0 {
        // 2. 获取父进程的 PID
        let parent_pid = (bpf_get_current_pid_tgid() >> 32) as u32;

        // 【第二道锁】：排除 Linux 祖宗进程 init(1) 和 kthreadd(2)
        // Zygote 的 PID 绝对不可能 <= 2
        if parent_pid > 2 {
            // 3. 获取父进程的名字
            let comm = bpf_get_current_comm().unwrap_or([0; 16]);
            let first_char = comm[0];

            // 【第三道锁】：宽松的首字母白名单 (安全精确化)
            // 包含 Android 所有可能的孵化器前缀：
            // z/Z: zygote, zygote64, ZygoteServer
            // u/U: usap32, usap64 (预加载池)
            // w: webview_zygote (网页容器孵化)
            // a: app_zygote (隔离进程孵化)
            if first_char == b'z'
                || first_char == b'Z'
                || first_char == b'u'
                || first_char == b'U'
                || first_char == b'w'
                || first_char == b'a'
            {
                // 此时，它 99.999% 是一个真正的 App 孵化事件！
                let child_pid_offset = 44;
                let child_pid: u32 = unsafe {
                    match ctx.read_at(child_pid_offset) {
                        Ok(val) => val,
                        Err(_) => return 0,
                    }
                };

                let event = ProcessEvent {
                    pid: child_pid,
                    _padding: 0,
                };
                EVENTS.output(&ctx, &event, 0);
            }
        }
    }

    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
