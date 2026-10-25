use aya_ebpf::{macros::map, maps::HashMap};
use wabbit_common::authorization::{Authorization, CgroupKey};

#[map]
pub static AUTHORIZATIONS: HashMap<CgroupKey, Authorization> = HashMap::with_max_entries(1024, 0);

// a map that maps cgroup ids to hashes of their name
// unimplemented!("map that maps cgroup ids to hashes of their name");
