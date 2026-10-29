use aya_ebpf::btf_maps::Array;

// btf_map full of cgroup ids
static mut CGROUP_IDS: Array<usize, { u8::MAX as usize }> = Array::new();

// function that checks if the current process is a member of a specified cgroup id, or has that id as one of its ancestors
