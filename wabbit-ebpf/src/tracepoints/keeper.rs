//! The yard keeper: fresh ids for the migration wall, at the moment of
//! creation.
//!
//! `PROTECTED_PATHS` maps a protected cgroupfs path (by its hash) to the
//! cgroup — the *yard* — that sat there when the loader populated the
//! map: its kernfs id, which the wall compares against the opening
//! caller's own cgroup and ancestors to tell the yard's insiders from
//! its outsiders. Kernfs ids are **per-inode-allocation state**: systemd
//! deletes a unit's cgroup when the unit exits and creates a fresh one
//! (a new id) when it starts again — and the fresh dir lands on the same
//! *path*, so the map's hash still matches while its id is stale. The
//! yard's own children then classify as outsiders and the wall kills the
//! unit at `EXIT_CGROUP` (measured: Rocky 9's `systemd-modules-load`
//! re-triggered 800ms after its first clean start failed with
//! `Operation not permitted` on exactly the recreated cgroup).
//!
//! The keeper closes that gap from the kernel, at the only causally
//! safe point: **creation**. Every `cgroup/cgroup_mkdir` event carries
//! the new cgroup's *live* id and its cgroupfs-relative path, so the
//! keeper — attached in the initrd, before systemd runs — refreshes the
//! entry keyed by the new cgroup's own full canonical path. No task can
//! be inside a cgroup before the cgroup exists, so by the time any child
//! is inside a fresh yard the map already carries its id: the wall's
//! insider rule cannot see a stale yard, and there is no window to
//! race. Only the new cgroup's own entry is written — a mkdir changes no
//! ancestor's id, and rewriting an ancestor's entry to a descendant's
//! id would poison it (measured: the self-test's sacrificial cgroup,
//! created *below* the trusted yard, must not refresh the yard).
//! Refreshing on *attach* (`cgroup_attach_task`) instead would be too
//! late by construction — the tracepoint fires inside the migrating
//! write, after the kernel has moved the task, and a concurrent child's
//! own `cgroup.procs` open lands between the two.
//!
//! The keeper never *creates* a protected path — it only rewrites the
//! id of an entry the loader already wrote, so a path the policy never
//! protected stays unprotected, and a hash of garbage (a misread record)
//! matches no key and writes nothing.
//!
//! `cgroup_mkdir`'s record layout is **distro-patched**: RHEL's
//! lazy-preempt backport pads the trace-entry header
//! (`common_preempt_lazy_count`), pushing every field out by 4 — so,
//! like the fork watchers, the keeper exists as two compiled variants
//! and the loader attaches the one whose `id`/`path` offsets match the
//! running kernel's own format file (both if it matches neither — a
//! misread record is inert, see above). The record's `path` is a
//! `__data_loc` string — a u32 encoding `(length << 16) | offset`
//! relative to the record — which the keeper resolves and hashes.

use aya_ebpf::{macros::tracepoint, programs::TracePointContext};
use aya_log_ebpf::info;

use wabbit_common::authorization::path_hash;

use crate::{
    lsm::{paths, trust},
    maps::PROTECTED_PATHS,
};

/// The vanilla `cgroup_mkdir` record: the 8-byte `trace_entry` header,
/// then `root`(int)@8, `level`(int)@12, `id`(u64)@16, and `path`'s
/// `__data_loc` u32 at 24.
const ID_VANILLA: usize = 16;
const PATH_VANILLA: usize = 24;

/// RHEL's lazy-preempt record: the `common_preempt_lazy_count` pad moves
/// `id` to 24 and `path`'s locator to 32. Verified against Rocky 9.8's
/// own format file (5.14.0-687.10.1.el9).
const ID_PREEMPT_LAZY: usize = 24;
const PATH_PREEMPT_LAZY: usize = 32;

/// Keep `PROTECTED_PATHS` fresh, for the vanilla record layout.
#[tracepoint(name = "cgroup_mkdir", category = "cgroup")]
pub fn yard_keeper_mkdir_vanilla(ctx: TracePointContext) -> i32 {
    keep_yards(ctx, ID_VANILLA, PATH_VANILLA)
}

/// Keep `PROTECTED_PATHS` fresh, for the RHEL lazy-preempt record layout.
#[tracepoint(name = "cgroup_mkdir", category = "cgroup")]
pub fn yard_keeper_mkdir_preempt_lazy(ctx: TracePointContext) -> i32 {
    keep_yards(ctx, ID_PREEMPT_LAZY, PATH_PREEMPT_LAZY)
}

/// Refresh the id of the protected path `hash` (already computed over
/// the full canonical path — see `keep_yards`) to `id`, keeping its
/// level: the path — the only thing that decides the level — did not
/// change.
#[inline(always)]
fn refresh_yard(ctx: &TracePointContext, hash: u64, id: u64) {
    if let Some(mut yard) = trust::protected(hash) {
        if yard.cgroup_id != id {
            info!(ctx, "yard keeper: path {:x} id {}", hash, id);
            yard.cgroup_id = id;
            let _ = unsafe { PROTECTED_PATHS.insert(&hash, yard, 0) };
        }
    }
}

/// Refresh the entry keyed by the new cgroup's own canonical path —
/// the one id a `cgroup_mkdir` event is authoritative for.
#[inline(always)]
fn keep_yards(ctx: TracePointContext, id_offset: usize, path_offset: usize) -> i32 {
    // The live id of the cgroup just created.
    let Ok(id) = (unsafe { ctx.read_at::<u64>(id_offset) }) else {
        return 0;
    };
    // `path` is a `__data_loc`: a u32 holding `(length << 16) | offset`
    // — see `__get_dynamic_array`/`__get_dynamic_array_len` in the
    // kernel's `trace_events.h` — both halves relative to the record.
    let Ok(data_loc) = (unsafe { ctx.read_at::<u32>(path_offset) }) else {
        return 0;
    };
    let data_offset = (data_loc & 0xffff) as usize;
    let data_len = ((data_loc >> 16) & 0xffff) as usize;
    if data_len == 0 {
        return 0;
    }

    // Hash the *whole* canonical path — `/sys/fs/cgroup` (a compile-time
    // prefix) plus the record's cgroupfs-relative path, which arrives
    // leading-slash. Only the entry keyed by the new cgroup's own full
    // path may be refreshed: the event's `id` is the *new* cgroup's, and
    // the ancestors above it keep their own (their cgroups already
    // existed — a child's creation changes no ancestor's id, so a
    // prefix match is a path that belongs to a *different* cgroup, and
    // rewriting it would pin that yard to a descendant's id — measured:
    // the self-test's own mkdir of its sacrificial cgroup poisoned the
    // trusted yard's entry and the wall then let the worker through, so
    // wabbit exited at its own self-test). The NUL that ends the record
    // string and the walk cap bound the loop; the result matches
    // `path_hash` of the canonical path, the loader's key convention.
    let mut hash = path_hash(paths::CGROUPFS_ROOT);
    let len = data_len.min(paths::PATH_WALK_CAP);
    let mut index = 0;
    while index < len {
        let Some(byte) = (unsafe { ctx.read_at::<u8>(data_offset + index) }).ok() else {
            break;
        };
        if byte == 0 {
            break;
        }
        hash = paths::fnv_step(hash, byte);
        index += 1;
    }
    refresh_yard(&ctx, hash, id);
    0
}