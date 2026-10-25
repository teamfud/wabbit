//! Launching the embedded wabbit binary.
//!
//! `wabbit-initrd`'s build script compiles the `wabbit` userspace binary and
//! embeds it as a blob (see `build.rs`), so the initrd carries its successor
//! with it and no filesystem has to provide one. This module turns the blob
//! back into a running process.
//!
//! # Executing a blob from an initrd
//!
//! `execve` only executes inodes, never raw bytes, so the blob has to be
//! materialized as one somewhere. The options, most to least preferred:
//!
//! 1. **`memfd_create` + `execveat` with `AT_EMPTY_PATH`** — an anonymous,
//!    executable inode that lives only in memory. Nothing appears on the
//!    initrd filesystem, no mount stays pinned after `switch_root` discards
//!    the initrd, and `/proc/<pid>/exe` reads `/memfd:wabbit (deleted)`
//!    forever after. Kernels since 6.6 can refuse to execute memfds
//!    (`vm.memfd_noexec`); creating the memfd with `MFD_EXEC` opts back in
//!    wherever the sysctl still allows it, and older kernels that reject the
//!    unknown flag outright get a retry without it.
//! 2. **Write the blob to a file on the initrd rootfs and execute that** —
//!    the startup diagram's original "copy wabbit to initrd". The initrd
//!    root is a writable ramfs, so this always works; the cost is a visible
//!    file, which lives only until the initrd is discarded.
//! 3. The same thing with extra steps — `O_TMPFILE` plus `linkat`, or a
//!    private tmpfs — buys nothing over (2) in an already writable ramfs.
//!
//! bpffs inodes carry no execute permission at all, so bnuuy's pin
//! directory can never serve as the materialization point.
//!
//! # Surviving systemd: `argv[0][0] == '@'`
//!
//! When systemd performs the `switch-root` transition out of the initrd, it
//! kills every process left running ("a killing spree of all running
//! processes", per systemd's initrd interface). Its `ignore_proc()` exempts
//! processes whose first `argv[0]` byte is `'@'` — the documented way for an
//! initrd process to live across the transition. wabbit is started with
//! `argv[0] = "@wabbit"` so it reaches the booted system.
//!
//! # Lifetime
//!
//! bnuuy's programs stay attached only as long as this process holds the
//! `aya::Ebpf` handle, so after starting wabbit the initrd babysits it
//! instead of exiting. In the full startup sequence the initrd eventually
//! exits at wabbit's request during the handoff; until that step exists,
//! this keeps the early protections enforced for wabbit's whole lifetime.

use std::{
    ffi::CString,
    fs::{self, File, Permissions},
    io::{self, Seek, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::{OsStrExt, OsStringExt},
            fs::PermissionsExt,
            process::CommandExt,
        },
    },
    path::Path,
    process::{Child, Command},
};

use anyhow::{Context, Result, bail};
use aya::{Ebpf, maps::HashMap};
use log::{debug, info, warn};

/// The wabbit userspace binary, compiled into this executable by `build.rs`.
const WABBIT_BLOB: &[u8] = include_bytes!(env!("WABBIT_BLOB"));

/// Where the file fallback materializes the blob.
const WABBIT_FILE: &str = "/wabbit";

/// The first byte marks the process as exempt from systemd's switch-root
/// kill; the rest is a name worth reading in a `ps` listing.
const WABBIT_ARG0: &str = "@wabbit";

/// `memfd_create` flags, from the kernel UAPI
/// (`include/uapi/linux/memfd.h`); libc does not export them for Linux.
const MFD_CLOEXEC: libc::c_uint = 0x0001;
const MFD_EXEC: libc::c_uint = 0x0010;

/// Start the embedded wabbit binary inside its cgroup, keep it trusted, and
/// babysit it.
///
/// Returns wabbit's exit code once it terminates. The child is spawned with
/// `argv[0][0] == '@'` so systemd's transition into the booted system spares
/// it (wabbit-initrd itself exits before `switch_root`; wabbit is the only
/// thing that crosses it), it is moved into `cgroup` — the wabbit cgroup the
/// authorization maps key on — before it can fork anything that would miss
/// the migration, and its PID is granted `bpf(2)` in bnuuy's trusted-PID
/// map, the early hook denying `bpf()` to everything but the PIDs
/// wabbit-initrd vouches for. The grant happens right after the fork, which
/// is safe because wabbit's first `bpf()` call sits far behind its
/// mount-namespace setup; making wabbit propagate that trust to the children
/// it spawns for itself is wabbit-side work that does not exist yet.
pub fn launch_embedded_wabbit(ebpf: &mut Ebpf, cgroup: &Path) -> Result<i32> {
    let mut child = spawn_wabbit()?;

    // Move wabbit into its cgroup immediately: cgroup membership is
    // inherited at fork, so everything wabbit spawns lands in the hierarchy
    // the authorization maps key on. wabbit's first fork sits behind its
    // mount-namespace setup, far enough away that this write — microseconds
    // after the spawn — always wins the race.
    fs::write(cgroup.join("cgroup.procs"), format!("{}\n", child.id()))
        .with_context(|| format!("moving wabbit into its cgroup at {}", cgroup.display()))?;

    let mut trusted_pids: HashMap<_, u32, u8> = ebpf
        .map_mut("TRUSTED_BPF_PIDS")
        .context("finding bnuuy trusted PID map")?
        .try_into()
        .context("opening bnuuy trusted PID map")?;
    trusted_pids
        .insert(child.id(), 1, 0)
        .context("trusting the wabbit PID in bnuuy")?;

    info!(
        "started embedded wabbit as pid {} (argv[0] {WABBIT_ARG0:?}) in its \
         cgroup at {}; babysitting it",
        child.id(),
        cgroup.display()
    );
    crate::sign::phase(&format!(
        "started embedded wabbit as pid {} in its cgroup at {}",
        child.id(),
        cgroup.display()
    ));
    let status = child.wait().context("waiting for wabbit")?;
    match status.code() {
        Some(code) => Ok(code),
        None => bail!("wabbit terminated by signal: {status}"),
    }
}

/// Spawn wabbit with its `@` marking, preferring the memfd route.
fn spawn_wabbit() -> Result<Child> {
    match spawn_via_memfd() {
        Ok(child) => {
            debug!("launched wabbit from an anonymous memfd");
            Ok(child)
        }
        Err(error) => {
            warn!(
                "launching wabbit from a memfd failed ({error:#}); \
                 falling back to a file on the initrd rootfs"
            );
            spawn_via_file()
        }
    }
}

/// Spawn wabbit from an anonymous executable memfd.
fn spawn_via_memfd() -> Result<Child> {
    let memfd = memfd_with_blob()?;
    // An FD_CLOEXEC memfd is inherited across fork and stays usable for the
    // execveat call in the child, then closes atomically when that exec
    // succeeds, so wabbit never sees the fd.
    let image = ExecImage::at_empty_path(memfd.as_raw_fd());
    spawn_with_image(image, "wabbit")
}

/// Spawn wabbit from a file written onto the initrd rootfs.
fn spawn_via_file() -> Result<Child> {
    fs::write(WABBIT_FILE, WABBIT_BLOB)
        .with_context(|| format!("writing the wabbit blob to {WABBIT_FILE}"))?;
    fs::set_permissions(WABBIT_FILE, Permissions::from_mode(0o755))
        .with_context(|| format!("making {WABBIT_FILE} executable"))?;
    let image = ExecImage::at_path(WABBIT_FILE)?;
    spawn_with_image(image, WABBIT_FILE)
}

/// Fork with the image's execveat hooked in before std's own exec.
///
/// The placeholder program is never executed: the hook replaces the forked
/// child first, and if it fails, `spawn` reports the failure.
fn spawn_with_image(image: ExecImage, placeholder: &str) -> Result<Child> {
    let mut command = Command::new(placeholder);
    // SAFETY: the closure only performs one async-signal-safe `execveat`
    // syscall on data prepared entirely before the fork; this process is
    // single-threaded, so there are no other threads' state or locks to
    // worry about.
    unsafe {
        command.pre_exec(move || Err(image.execveat()));
    }
    Ok(command.spawn()?)
}

/// Create an executable memfd holding the wabbit blob.
fn memfd_with_blob() -> Result<File> {
    let name = CString::new("wabbit").expect("the memfd name contains no NUL");
    let mut fd = unsafe { libc::memfd_create(name.as_ptr(), MFD_CLOEXEC | MFD_EXEC) };
    if fd < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
        // The kernel predates MFD_EXEC (6.6); on those, memfds are
        // executable by default.
        debug!("MFD_EXEC rejected; retrying without it");
        fd = unsafe { libc::memfd_create(name.as_ptr(), MFD_CLOEXEC) };
    }
    if fd < 0 {
        return Err(io::Error::last_os_error()).context("memfd_create for the wabbit blob");
    }
    let mut memfd = unsafe { File::from_raw_fd(fd) };
    memfd
        .write_all(WABBIT_BLOB)
        .context("writing the wabbit blob to the memfd")?;
    memfd.rewind().context("rewinding the wabbit memfd")?;
    Ok(memfd)
}

/// Everything an `execveat` needs, built before the fork because `pre_exec`
/// closures must not allocate.
struct ExecImage {
    dirfd: libc::c_int,
    path: CString,
    flags: libc::c_int,
    // Never read through Rust: their bytes back the pointer arrays and must
    // stay alive until the execveat in the forked child has consumed them.
    #[expect(
        dead_code,
        reason = "the strings back the argv/envp pointers; see the field comment"
    )]
    argv: Vec<CString>,
    argv_pointers: ExecPointers,
    #[expect(
        dead_code,
        reason = "the strings back the argv/envp pointers; see the field comment"
    )]
    envp: Vec<CString>,
    envp_pointers: ExecPointers,
}

/// Pointers into the C strings of an [`ExecImage`], made `Send + Sync` for
/// the `pre_exec` closure, which requires both. The pointers reference the
/// `ExecImage`'s own strings and are only handed to the kernel (inside the
/// forked child, single-threaded) while that image is alive and unmoved.
#[derive(Clone)]
struct ExecPointers(Vec<*const libc::c_char>);
// SAFETY: see the struct documentation.
unsafe impl Send for ExecPointers {}
// SAFETY: see the struct documentation.
unsafe impl Sync for ExecPointers {}

impl ExecImage {
    /// Execute the file behind `dirfd`; the empty path selects it via
    /// `AT_EMPTY_PATH`.
    fn at_empty_path(dirfd: libc::c_int) -> Self {
        Self::new(
            dirfd,
            CString::new("").expect("empty path"),
            libc::AT_EMPTY_PATH,
        )
    }

    /// Execute `path` relative to the working directory.
    fn at_path(path: &str) -> Result<Self> {
        Ok(Self::new(
            libc::AT_FDCWD,
            CString::new(path).with_context(|| format!("{path:?} contains a NUL"))?,
            0,
        ))
    }

    fn new(dirfd: libc::c_int, path: CString, flags: libc::c_int) -> Self {
        let argv = vec![CString::new(WABBIT_ARG0).expect("argv contains no NUL")];
        let argv_pointers = ExecPointers(c_pointers(&argv));
        let envp = environment();
        let envp_pointers = ExecPointers(c_pointers(&envp));
        Self {
            dirfd,
            path,
            flags,
            argv,
            argv_pointers,
            envp,
            envp_pointers,
        }
    }

    /// Replace the current process; returns the failure reason if it ever
    /// returns at all.
    fn execveat(&self) -> io::Error {
        unsafe {
            libc::syscall(
                libc::SYS_execveat,
                self.dirfd,
                self.path.as_ptr(),
                self.argv_pointers.0.as_ptr(),
                self.envp_pointers.0.as_ptr(),
                self.flags,
            );
        }
        io::Error::last_os_error()
    }
}

/// The current environment as a NUL-terminated C string array.
fn environment() -> Vec<CString> {
    std::env::vars_os()
        .filter_map(|(key, value)| {
            let mut entry = key.into_vec();
            entry.push(b'=');
            entry.extend_from_slice(value.as_bytes());
            // Environment entries cannot contain NUL bytes anyway; an
            // OsString that smuggles one in is dropped rather than trusted.
            CString::new(entry).ok()
        })
        .collect()
}

/// The pointers to `strings` as a kernel argv/envp array: the items, then a
/// terminating null pointer.
fn c_pointers(strings: &[CString]) -> Vec<*const libc::c_char> {
    strings
        .iter()
        .map(|string| string.as_ptr())
        .chain([std::ptr::null()])
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_is_an_elf_executable() {
        assert_eq!(
            &WABBIT_BLOB[..4],
            b"\x7fELF",
            "the embedded blob is not an ELF executable"
        );
    }

    #[test]
    fn exec_pointer_arrays_are_nul_terminated() {
        let argv = vec![CString::new(WABBIT_ARG0).unwrap()];
        let pointers = c_pointers(&argv);
        assert_eq!(pointers.len(), 2);
        assert!(!pointers[0].is_null());
        assert!(pointers[1].is_null());
    }

    #[test]
    fn env_entries_survive_the_c_string_conversion() {
        // SAFETY: this is the only environment mutation in the test binary,
        // and no other test reads the environment while it runs.
        unsafe { std::env::set_var("WABBIT_LAUNCH_TEST", "value") };
        let env = environment();
        let entry = env
            .iter()
            .find(|entry| entry.to_bytes().starts_with(b"WABBIT_LAUNCH_TEST="))
            .expect("the variable is in the environment");
        assert_eq!(entry.to_bytes(), b"WABBIT_LAUNCH_TEST=value");
    }
}
