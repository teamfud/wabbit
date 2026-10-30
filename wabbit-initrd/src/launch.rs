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
//! `aya::Ebpf` handle. The handoff (`docs/startup.mermaid`) ends that
//! handle's life deliberately, by exchange:
//!
//! 1. this process announces `trusted` — the `bpf(2)` grant has landed in
//!    bnuuy's `TRUSTED_BPF_PIDS` map. `wabbit` waits for it before its
//!    first `bpf(2)` call (the guard object's first map create): both
//!    sides run after the same fork, and without the rendezvous the create
//!    can read the trust map before the insert and be denied — a failure
//!    measured as nondeterministic across boots of the same artifact;
//! 2. `wabbit` announces `ready` once its guard is enforcing and
//!    self-tested;
//! 3. this process runs its pre-shutdown self-test (the workers spawn from
//!    outside every trust map; the enforcing guard — plus bnuuy's shadowing
//!    gates, still attached — must deny each one), then answers `die`;
//! 4. `wabbit` answers `ack`, this process exits, and its `Ebpf` handle —
//!    and with it every bnuuy link — drops: the early protections end
//!    exactly here, by design, and `wabbit`'s guard carries the enforcement
//!    alone across `switch_root`.
//!
//! The world stays frozen through the whole exchange: it thaws when this
//! process returns, on the resume in `main` — which is what releases the
//! init to run `switch_root` in the first place.

use std::{
    ffi::CString,
    fs::{self, File, Permissions},
    io::{self, Read, Seek, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::{
            ffi::{OsStrExt, OsStringExt},
            fs::PermissionsExt,
            net::UnixStream,
            process::CommandExt,
        },
    },
    path::Path,
    process::{Child, Command},
};

use anyhow::{Context, Result, bail};
use aya::{Ebpf, maps::HashMap};
use log::{debug, info, warn};
use wabbit_common::{brand::NAME, handoff};

/// The wabbit userspace binary, compiled into this executable by `build.rs`.
const WABBIT_BLOB: &[u8] = include_bytes!(env!("WABBIT_BLOB"));

/// Where the file fallback materializes the blob: the brand name at the
/// initramfs root.
fn blob_file() -> String {
    format!("/{NAME}")
}

/// `argv[0]` of the outer process. The first byte marks it as exempt from
/// systemd's switch-root kill; the rest is a name worth reading in a
/// `ps` listing.
fn arg0() -> String {
    format!("@{NAME}")
}

/// `memfd_create` flags, from the kernel UAPI
/// (`include/uapi/linux/memfd.h`); libc does not export them for Linux.
const MFD_CLOEXEC: libc::c_uint = 0x0001;
const MFD_EXEC: libc::c_uint = 0x0010;

/// Start the embedded wabbit binary inside its cgroup, keep it trusted, and
/// run the handoff exchange with it.
///
/// Returns once the handoff completes: `wabbit` has acknowledged the
/// go-ahead and runs on, this process exits right after it (its bnuuy links
/// detach with it), and the caller's world resume releases the init into
/// `switch_root`. The child is spawned with `argv[0][0] == '@'` so
/// systemd's transition into the booted system spares
/// it (wabbit-initrd itself exits before `switch_root`; wabbit is the only
/// thing that crosses it), it is moved into `cgroup` — the wabbit cgroup the
/// authorization maps key on — before it can fork anything that would miss
/// the migration, and its PID is granted `bpf(2)` in bnuuy's trusted-PID
/// map, the early hook denying `bpf()` to everything but the PIDs
/// wabbit-initrd vouches for. The grant happens right after the fork, which
/// is safe because wabbit's first `bpf()` call sits far behind its
/// mount-namespace setup; making wabbit propagate that trust to the children
/// it spawns for itself is wabbit-side work that does not exist yet.
pub fn launch_embedded_wabbit(ebpf: &mut Ebpf, cgroup: &Path) -> Result<()> {
    // The handoff socket: wabbit's end is duped to a fixed descriptor in
    // the child (see `spawn_with_image`), its number travels in the
    // environment, and the messages are `wabbit_common::handoff`.
    let (mut socket, wabbit_end) = handoff_socketpair()?;
    let child = spawn_wabbit(wabbit_end.as_raw_fd())?;
    // This process's own copy of wabbit's end is done; the fork holds the
    // child's.
    drop(wabbit_end);

    // Move wabbit into its cgroup immediately: cgroup membership is
    // inherited at fork, so everything wabbit spawns lands in the hierarchy
    // the authorization maps key on. wabbit's first fork sits behind its
    // mount-namespace setup, far enough away that this write — microseconds
    // after the spawn — always wins the race.
    fs::write(cgroup.join("cgroup.procs"), format!("{}\n", child.id()))
        .with_context(|| format!("moving {NAME} into its cgroup at {}", cgroup.display()))?;

    let mut trusted_pids: HashMap<_, u32, u8> = ebpf
        .map_mut("TRUSTED_BPF_PIDS")
        .context("finding the trusted-PID map")?
        .try_into()
        .context("opening the trusted-PID map")?;
    trusted_pids
        .insert(child.id(), 1, 0)
        .context("trusting the child PID in the trusted-PID map")?;

    // Announce the grant on the handoff socket: wabbit waits for this
    // message before its first `bpf(2)` call. The grant races that call —
    // both sides run after the same fork, and nothing else orders them:
    // the guard object's map creates can read the trust map before the
    // insert lands, and be denied (`EPERM`) — measured in the lab as
    // nondeterministic across boots of the same artifact. The message
    // makes it a rendezvous.
    socket
        .write_all(handoff::TRUSTED)
        .context("announcing the bpf(2) trust grant on the handoff socket")?;

    let argv0 = arg0();
    info!(
        "started embedded {NAME} as pid {} (argv[0] {argv0:?}) in its \
         cgroup at {}; waiting for its readiness",
        child.id(),
        cgroup.display()
    );
    crate::sign::phase(&format!(
        "started embedded {NAME} as pid {} in its cgroup at {}",
        child.id(),
        cgroup.display()
    ));

    // "ready for you to back off": wabbit's guard is enforcing. An EOF
    // instead means wabbit died before announcing anything — the caller's
    // world resume thaws the boot either way, and the sign explains it.
    match read_message(&mut socket)? {
        Some(message) if message == "ready" => {}
        Some(message) => bail!("unexpected handoff message {message:?} from {NAME}"),
        None => bail!("{NAME} exited before announcing readiness"),
    }

    // The pre-shutdown self-test, while the world is still frozen: the
    // workers spawn from this PID, outside every trust map, and the
    // enforcing protections must deny each one.
    info!("{NAME} is ready; running the pre-shutdown self-test from spawned workers");
    crate::sign::phase(&format!(
        "{NAME} announced readiness; running the pre-shutdown self-test"
    ));
    crate::verify::verify_handoff()?;

    // "i'm ready to die": the go-ahead. wabbit's ack releases it to cross
    // switch_root on its own; this process exits right after the caller
    // resumes the world.
    socket
        .write_all(handoff::DIE)
        .context("sending the handoff go-ahead")?;
    match read_message(&mut socket)? {
        Some(message) if message == "ack" => {}
        Some(message) => bail!("unexpected handoff message {message:?} from {NAME}"),
        None => bail!("{NAME} exited at the handoff instead of acknowledging"),
    }
    info!("the handoff is complete: {NAME} runs on; this process exits before switch_root");
    crate::sign::phase(&format!(
        "handoff complete: the pre-shutdown self-test passed, {NAME} \
         acknowledged, and this process exits before switch_root"
    ));
    drop(socket);
    // The child outlives this process by design: the caller exits, the
    // kernel reparents wabbit to init, and no zombie is left behind (init
    // reaps what this handle would have).
    drop(child);
    Ok(())
}

/// The socketpair for the handoff: this process's end returned as a stream,
/// wabbit's end as a plain descriptor for the `dup2` into the child. Both
/// ends are `SOCK_CLOEXEC`, so nothing this process execs afterwards — the
/// pre-shutdown self-test workers above all — inherits either.
fn handoff_socketpair() -> Result<(UnixStream, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: one socketpair(2) into a fully-sized array.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error()).context("socketpair for the handoff");
    }
    // SAFETY: both descriptors were just created and are owned solely by
    // this process from here.
    let ours = unsafe { UnixStream::from_raw_fd(fds[0]) };
    let wabbit = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    Ok((ours, wabbit))
}

/// Read one `\n`-terminated handoff message. `Ok(None)` is a clean EOF: the
/// other side — `wabbit` — closed its socket.
fn read_message(socket: &mut UnixStream) -> Result<Option<String>> {
    let mut message = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match socket.read(&mut byte) {
            Ok(0) => {
                if message.is_empty() {
                    return Ok(None);
                }
                bail!(
                    "the handoff message {:?} is not newline-terminated",
                    message
                );
            }
            Ok(_) if byte[0] == b'\n' => return Ok(Some(String::from_utf8(message)?)),
            Ok(_) => message.push(byte[0]),
            Err(error) => return Err(error).context("reading a handoff message"),
        }
        if message.len() > 64 {
            bail!("the handoff message is longer than any sent");
        }
    }
}

/// Spawn wabbit with its `@` marking, preferring the memfd route.
fn spawn_wabbit(handoff_fd: RawFd) -> Result<Child> {
    match spawn_via_memfd(handoff_fd) {
        Ok(child) => {
            debug!("launched {NAME} from an anonymous memfd");
            Ok(child)
        }
        Err(error) => {
            warn!(
                "launching {NAME} from a memfd failed ({error:#}); \
                 falling back to a file on the initrd rootfs"
            );
            spawn_via_file(handoff_fd)
        }
    }
}

/// Spawn wabbit from an anonymous executable memfd.
fn spawn_via_memfd(handoff_fd: RawFd) -> Result<Child> {
    let memfd = memfd_with_blob()?;
    // An FD_CLOEXEC memfd is inherited across fork and stays usable for the
    // execveat call in the child, then closes atomically when that exec
    // succeeds, so wabbit never sees the fd.
    let image = ExecImage::at_empty_path(memfd.as_raw_fd());
    spawn_with_image(image, NAME, handoff_fd)
}

/// Spawn wabbit from a file written onto the initrd rootfs.
fn spawn_via_file(handoff_fd: RawFd) -> Result<Child> {
    let file = blob_file();
    fs::write(&file, WABBIT_BLOB).with_context(|| format!("writing the {NAME} blob to {file}"))?;
    fs::set_permissions(&file, Permissions::from_mode(0o755))
        .with_context(|| format!("making {file} executable"))?;
    let image = ExecImage::at_path(&file)?;
    spawn_with_image(image, &file, handoff_fd)
}

/// Fork with the image's execveat hooked in before std's own exec.
///
/// The placeholder program is never executed: the hook replaces the forked
/// child first, and if it fails, `spawn` reports the failure. Before the
/// exec, the handoff socket is duped to its fixed descriptor — `dup2`
/// clears `FD_CLOEXEC` on the copy, so the socket crosses the exec while
/// every other descriptor this process marked `CLOEXEC` does not.
fn spawn_with_image(image: ExecImage, placeholder: &str, handoff_fd: RawFd) -> Result<Child> {
    let mut command = Command::new(placeholder);
    // SAFETY: the closure only performs one async-signal-safe `dup2`
    // syscall on a descriptor prepared entirely before the fork; this
    // process is single-threaded, so there are no other threads' state or
    // locks to worry about.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(handoff_fd, handoff::SOCKET_FD) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    // SAFETY: as above, one async-signal-safe `execveat` on data prepared
    // before the fork.
    unsafe {
        command.pre_exec(move || Err(image.execveat()));
    }
    Ok(command.spawn()?)
}

/// Create an executable memfd holding the wabbit blob. Its name — the
/// brand — is what `/proc/<pid>/exe` and the process's `comm` show.
fn memfd_with_blob() -> Result<File> {
    let name = CString::new(NAME).expect("the memfd name contains no NUL");
    let mut fd = unsafe { libc::memfd_create(name.as_ptr(), MFD_CLOEXEC | MFD_EXEC) };
    if fd < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
        // The kernel predates MFD_EXEC (6.6); on those, memfds are
        // executable by default.
        debug!("MFD_EXEC rejected; retrying without it");
        fd = unsafe { libc::memfd_create(name.as_ptr(), MFD_CLOEXEC) };
    }
    if fd < 0 {
        return Err(io::Error::last_os_error())
            .context(format!("memfd_create for the {NAME} blob"));
    }
    let mut memfd = unsafe { File::from_raw_fd(fd) };
    memfd
        .write_all(WABBIT_BLOB)
        .context(format!("writing the {NAME} blob to the memfd"))?;
    memfd
        .rewind()
        .context(format!("rewinding the {NAME} memfd"))?;
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
        let argv = vec![CString::new(arg0()).expect("argv contains no NUL")];
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

/// The current environment as a NUL-terminated C string array, plus the
/// handoff descriptor's number (`wabbit` reads it to find the socket this
/// process's `dup2` placed at `wabbit_common::handoff::SOCKET_FD`).
fn environment() -> Vec<CString> {
    let mut entries: Vec<CString> = std::env::vars_os()
        .filter_map(|(key, value)| {
            let mut entry = key.into_vec();
            entry.push(b'=');
            entry.extend_from_slice(value.as_bytes());
            // Environment entries cannot contain NUL bytes anyway; an
            // OsString that smuggles one in is dropped rather than trusted.
            CString::new(entry).ok()
        })
        .collect();
    let handoff_var = format!(
        "{}_HANDOFF_FD={}",
        wabbit_common::brand::ENV_PREFIX,
        handoff::SOCKET_FD
    );
    entries.push(CString::new(handoff_var).expect("the handoff variable holds no NUL"));
    entries
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
        let argv = vec![CString::new(arg0()).unwrap()];
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

    #[test]
    fn the_environment_carries_the_handoff_descriptor() {
        let env = environment();
        let expected = format!(
            "{}_HANDOFF_FD={}",
            wabbit_common::brand::ENV_PREFIX,
            handoff::SOCKET_FD
        );
        assert!(
            env.iter()
                .any(|entry| entry.to_bytes() == expected.as_bytes()),
            "the handoff descriptor's variable is missing from the child environment"
        );
    }
}
