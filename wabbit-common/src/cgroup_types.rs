pub struct CgroupPerm {
    /// redundant but useful: id of cgroup policy
    pub cgroup_id: usize,
    /// grant this cgroup supervisory access to wabbit and its cgroup facilities as a whole. allows it to take actions that might endanger wabbit
    pub supv: bool,
    /// allow this cgroup to see and move its processes into the wabbit private mount namespace
    pub priv_ns: bool,
    /// other cgroup permissions
    pub perms: GlobalPerm,
}

pub struct GlobalPerm {
    /// allow mounting filesystems
    pub allow_mount: bool,
    /// allow use of the bpf() syscall
    pub allow_bpf: bool,
    /// allow writing to mounts not mounted NOEXEC
    pub allow_writing_execable_folders: bool,
    /// allow executing from mounts not mounted RDONLY
    pub allow_execing_writable_folders: bool,
    /// allow writing to the cgroupfs
    pub allow_writing_cgroupfs: bool,
    /// allow processes to capture raw network traffic
    pub allow_raw_network_capture: bool,

    /// [TAUNT]: block reading /sys/kernel/btf to be REALLY petty about blocking ebpf programs from loading
    pub block_sys_kernel_btf_read: bool,
}
