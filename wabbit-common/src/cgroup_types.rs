pub struct CgroupPerm {
    /// redundant because of hashmap: hash of cgroup path
    pub cgroup_id: usize,
    /// grant this cgroup supervisory access to wabbit and its cgroup facilities as a whole. allows it to take actions that might endanger wabbit
    pub supv: bool,
    /// allow this cgroup to see and move its processes into the wabbit private mount namespace
    pub priv_ns: bool,
    /// protect this cgroup from having its processes killed, debugged or sabotaged
    pub protect: bool,
    /// other cgroup permissions
    pub perms: GlobalPerm,
}

pub struct GlobalPerm {
    /// allow mounting filesystems
    pub allow_mount: bool,
    /// allow use of the bpf() syscall
    pub allow_bpf: bool,
    /// allow loading and managing kernel modules
    pub allow_kmods: bool,
    /// allow writing to mounts not mounted NOEXEC
    pub allow_writing_execable_folders: bool,
    /// allow executing from mounts not mounted RDONLY
    pub allow_execing_writable_folders: bool,
    /// allow writing to the cgroupfs, other than wabbit's processes
    pub allow_writing_cgroupfs: bool,
    /// allow capture of raw network traffic
    pub allow_raw_network_capture: bool,
    /// allow binding sockets
    pub allow_bind_net_sockets: bool,
    /// allow binding unix sockets
    pub allow_bind_local_sockets: bool,
    /// allow debugging the kernel and other processes
    pub allow_debugging: bool,
    /// allow processes other than systemd to communicate with it and modify unit files
    pub allow_systemd: bool,
    /// allow use of ACPI or reboot() syscall
    pub allow_power_management: bool,
    /// allow modifying iptables/nftables rules
    pub allow_modifying_firewall: bool,
    /// allow sending signals to processes outside of own cgroup
    pub allow_signaling_other_cgroups: bool,
    /// id of path profile map to follow
    pub path_profile_map: u32,
}

pub struct PathProfile {
    pub create: PathAction,
    pub read: PathAction,
    pub write: PathAction,
}

pub enum PathAction {
    /// allow the action
    Allow,
    /// claim the target file doesn't exist (only use for read)
    Enoent,
    /// deny the action by permission
    Eperm,
    /// send a SIGKILL signal to the calling process
    Sigkill,
    /// send a SIGILL signal to the calling process
    Sigill,
    /// send a SIGSEGV signal to the calling process
    Sigsegv,
    /// log the action and allow it to continue
    Flag,
}
