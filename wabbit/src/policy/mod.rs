//! Policy loading: the `wabbit` side of [`wabbit_policy`].
//!
//! The format (types, signing, verification) lives in the `wabbit-policy`
//! crate; this module re-exports the pieces the existing callers use
//! (`main.rs`, `ipc.rs`, the filesystem appliers) so they don't churn with
//! the crate boundary.

/// The `authorization` section types.
pub use wabbit_policy::authorization;
/// The `rootfs` section types.
pub use wabbit_policy::rootfs;
pub use wabbit_policy::{
    PRIVATE_KEY_SIZE, Policy, from_bytes, read_file, sign, to_signed_bytes, write_new_signed,
};
