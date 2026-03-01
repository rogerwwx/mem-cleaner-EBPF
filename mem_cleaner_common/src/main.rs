#![no_std]

// 确保内存布局在 C (eBPF) 和 Rust (用户态) 之间一致
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessEvent {
    pub pid: u32,
    pub uid: u32,
}

// 仅在用户态编译时实现 Aya 的 Pod trait (允许安全地从字节转换)
#[cfg(feature = "user")]
unsafe impl aya::Pod for ProcessEvent {}
