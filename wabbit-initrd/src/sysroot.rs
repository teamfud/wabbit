//! Waiting for the real root filesystem.
//!
//! The startup sequence polls until the initrd has mounted the real root
//! ("begin poll for /sysroot ... notify of sysroot being mounted") and then
//! stops the world again, so the handoff steps cannot race anyone. Where the
//! root lands and when it is *finished* depend on the initrd:
//!
//! * dracut and systemd initrds mount it at `/sysroot`
//!   (`dracut.bootup(7)`, systemd's initrd interface). The nested
//!   filesystems follow *after* the root itself, and only then does the
//!   initrd proceed to the handoff:
//!
//!   ```text
//!   sysroot.mount
//!     → initrd-parse-etc.service
//!     → sysroot-usr.mount and mounts marked x-initrd.mount
//!     → initrd-fs.target
//!     → ... → switch-root
//!   ```
//!
//!   `initrd-parse-etc.service` mounts what the root's own `/etc/fstab`
//!   announces: a separate `/usr`, and any entry carrying the
//!   `x-initrd.mount` option.
//!
//! * initramfs-tools mounts it at `/root` (`rootmnt`, see
//!   `initramfs-tools(7)`), runs its `local-bottom` scripts, and has no
//!   fstab-driven nested-mount phase of its own.
//!
//! Freezing before the nested filesystems are in place would hand `wabbit`
//! an incomplete root (its configuration and policy live there), so
//! [`wait_for_sysroot`] requires all of:
//!
//! 1. a mount at `/sysroot` or `/root`, whichever the initrd provides;
//! 2. every nested mount the root's fstab announces (`/usr` and
//!    `x-initrd.mount` entries), detected as mounts below the root;
//! 3. a few consecutive polls with no changes to the mounts below the
//!    root — the nested mounts appear *after* the root, and no initrd
//!    documents a moment that is safe to observe directly.
//!
//! The fstab expectations are advisory: if the root and its mounts stay
//! quiet long enough without one appearing (an initrd that does not mount
//! what its fstab announces, an fstab we cannot parse), the wait ends with
//! a warning rather than hanging the boot.

use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use anyhow::{Context, Result};
use log::{debug, info, warn};

/// Where initrds mount the real root: `/sysroot` for dracut and systemd
/// initrds, `/root` for initramfs-tools.
const ROOT_MOUNT_POINTS: &[&str] = &["/sysroot", "/root"];

/// The fstab option that marks an entry the initrd itself mounts during its
/// `initrd-parse-etc` phase (`dracut.bootup(7)`).
const INITRD_MOUNT_OPTION: &str = "x-initrd.mount";

/// The kernel's view of the mount table.
const MOUNTINFO: &str = "/proc/self/mountinfo";

/// How often to poll the mount table.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// How many consecutive unchanged polls settle the mount set. The nested
/// mounts appear shortly after the root, so a quiet quarter second is a
/// settled initrd.
const QUIESCENCE_POLLS: u32 = 5;

/// How many consecutive unchanged polls override unmet fstab expectations
/// (10 seconds): the initrd is not going to mount them.
const EXPECTATION_TIMEOUT_POLLS: u32 = 200;

/// The real root as mounted by the initrd.
#[derive(Debug)]
pub struct Sysroot {
    /// Where the initrd mounted it: `/sysroot` or `/root`.
    pub mount_point: PathBuf,
}

/// Wait for the real root and its nested filesystems to be mounted.
pub fn wait_for_sysroot() -> Result<Sysroot> {
    info!(
        "waiting for the real root to be mounted at {}",
        ROOT_MOUNT_POINTS.join(" or ")
    );

    let mut mounted_root = false;
    let mut snapshot: Vec<String> = Vec::new();
    let mut quiet_polls: u32 = 0;
    loop {
        let mounts = mount_points().context("reading the mount table")?;

        let Some(root) = root_mount_point(&mounts) else {
            if mounted_root {
                warn!(
                    "the mounted root disappeared (a switch-root racing us?); \
                     waiting for it to be mounted again"
                );
                mounted_root = false;
            }
            snapshot.clear();
            quiet_polls = 0;
            thread::sleep(POLL_INTERVAL);
            continue;
        };
        if !mounted_root {
            mounted_root = true;
            info!("the real root appeared at {root}");
        }

        let nested = mounts_under(&mounts, root);
        if nested != snapshot {
            debug!("mounts below {root} changed: {nested:?}");
            snapshot = nested;
            quiet_polls = 0;
        } else {
            quiet_polls += 1;
        }

        let missing = missing_expected_mounts(root, &mounts, &fstab_entries(root));
        if missing.is_empty() {
            if quiet_polls >= QUIESCENCE_POLLS {
                return Ok(Sysroot {
                    mount_point: PathBuf::from(root),
                });
            }
        } else if quiet_polls == QUIESCENCE_POLLS {
            debug!("waiting for the nested mounts {missing:?} below {root}");
        } else if quiet_polls >= EXPECTATION_TIMEOUT_POLLS {
            warn!(
                "{root} is mounted and quiet, but its fstab announces mounts \
                 that never appeared ({missing:?}); proceeding anyway"
            );
            return Ok(Sysroot {
                mount_point: PathBuf::from(root),
            });
        }

        thread::sleep(POLL_INTERVAL);
    }
}

/// The first mount, in mount order, at one of [`ROOT_MOUNT_POINTS`].
fn root_mount_point(mounts: &[String]) -> Option<&str> {
    mounts
        .iter()
        .map(String::as_str)
        .find(|mount| ROOT_MOUNT_POINTS.contains(mount))
}

/// Every mount at or below `root`, in mount order. Mount order is stable
/// across polls, so two equal vectors mean nothing changed.
fn mounts_under(mounts: &[String], root: &str) -> Vec<String> {
    let prefix = format!("{root}/");
    mounts
        .iter()
        .filter(|mount| mount.as_str() == root || mount.starts_with(&prefix))
        .cloned()
        .collect()
}

/// The nested mounts the root's fstab announces that have not been mounted.
fn missing_expected_mounts(root: &str, mounts: &[String], fstab: &[FstabEntry]) -> Vec<String> {
    expected_nested_mounts(fstab)
        .iter()
        .map(|point| format!("{root}{point}"))
        .filter(|path| !mounts.iter().any(|mount| mount == path))
        .collect()
}

/// The mount points from `/proc/self/mountinfo`, in mount order.
fn mount_points() -> std::io::Result<Vec<String>> {
    let mountinfo = fs::read_to_string(MOUNTINFO)?;
    Ok(mountinfo.lines().filter_map(mount_point_of).collect())
}

/// The mount point (the fifth field) of one mountinfo line.
fn mount_point_of(line: &str) -> Option<String> {
    line.split_whitespace().nth(4).map(unescape)
}

/// One entry of the mounted root's `/etc/fstab`.
struct FstabEntry {
    mount_point: String,
    options: String,
}

/// Parse an fstab, skipping comments and blanks. A malformed line is
/// skipped, not trusted.
fn parse_fstab(content: &str) -> Vec<FstabEntry> {
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let mut fields = line.split_whitespace();
            let _spec = fields.next()?;
            let mount_point = fields.next()?;
            let _fstype = fields.next()?;
            let options = fields.next().unwrap_or_default();
            Some(FstabEntry {
                mount_point: unescape(mount_point),
                options: options.to_owned(),
            })
        })
        .collect()
}

/// Read the mounted root's fstab, if it has one.
fn fstab_entries(root: &str) -> Vec<FstabEntry> {
    let fstab = Path::new(root).join("etc/fstab");
    match fs::read_to_string(&fstab) {
        Ok(content) => parse_fstab(&content),
        // An unreadable fstab announces nothing; the quiescence requirement
        // still applies.
        Err(_) => Vec::new(),
    }
}

/// The nested mount points an initrd is expected to mount below the root:
/// the same set `initrd-parse-etc.service` mounts from the root's fstab —
/// a separate `/usr`, and every entry marked `x-initrd.mount`.
fn expected_nested_mounts(fstab: &[FstabEntry]) -> BTreeSet<String> {
    fstab
        .iter()
        .filter(|entry| {
            entry.mount_point.starts_with('/')
                && entry.mount_point != "/"
                && (entry.mount_point == "/usr"
                    || entry
                        .options
                        .split(',')
                        .any(|option| option == INITRD_MOUNT_OPTION))
        })
        .map(|entry| entry.mount_point.clone())
        .collect()
}

/// Decode the octal escapes mountinfo and fstab use for whitespace and
/// backslashes (for example `\040` for a space). A sequence that is not a
/// valid byte escape — not three octal digits, or a value above 0o377 — is
/// left as it is.
fn unescape(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' && index + 3 < bytes.len() {
            let octal = &bytes[index + 1..index + 4];
            let escaped = std::str::from_utf8(octal)
                .ok()
                .filter(|octal| octal.bytes().all(|digit| (b'0'..=b'7').contains(&digit)))
                .and_then(|octal| u32::from_str_radix(octal, 8).ok())
                .and_then(|value| u8::try_from(value).ok());
            if let Some(byte) = escaped {
                decoded.push(byte);
                index += 4;
                continue;
            }
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOUNTINFO: &str = "\
420 27 0:26 / /sysroot rw,relatime - btrfs /dev/mapper/root rw
421 420 0:27 / /sysroot/usr rw,relatime - ext4 /dev/sda2 rw
422 420 0:28 / /sysroot/var/lib/thing rw,relatime - ext4 /dev/sda3 rw
423 27 0:29 / /root rw,relatime - ext4 /dev/sdb1 rw
424 27 0:30 / /media/backup\\040disk rw,relatime - ext4 /dev/sdc1 rw
";

    #[test]
    fn mount_points_parse_in_order() {
        let mounts = MOUNTINFO
            .lines()
            .filter_map(mount_point_of)
            .collect::<Vec<_>>();
        assert_eq!(
            mounts,
            [
                "/sysroot",
                "/sysroot/usr",
                "/sysroot/var/lib/thing",
                "/root",
                "/media/backup disk",
            ]
        );
    }

    #[test]
    fn root_mount_points_are_exact_matches() {
        let mounts = ["/sysroot".to_owned(), "/sysroot2".to_owned()];
        assert_eq!(root_mount_point(&mounts), Some("/sysroot"));
        let mounts = ["/rootkit".to_owned()];
        assert_eq!(root_mount_point(&mounts), None);
    }

    #[test]
    fn mounts_below_a_root_respect_boundaries() {
        let mounts = MOUNTINFO
            .lines()
            .filter_map(mount_point_of)
            .collect::<Vec<_>>();
        assert_eq!(
            mounts_under(&mounts, "/sysroot"),
            ["/sysroot", "/sysroot/usr", "/sysroot/var/lib/thing"]
        );
        // `/rootkit` must not count as below `/root`.
        assert_eq!(mounts_under(&mounts, "/root"), ["/root"]);
    }

    #[test]
    fn fstab_comments_and_blanks_are_skipped() {
        let fstab = "\
# a comment
/dev/sda2 /usr ext4 defaults 0 2

/dev/sda1 / ext4 defaults 0 1
/dev/sda3 /var/lib/thing ext4 defaults,x-initrd.mount,x-systemd.automount 0 2
/dev/sdb1 none swap sw 0 0
";
        let entries = parse_fstab(fstab);
        let expected = expected_nested_mounts(&entries);
        assert_eq!(
            expected,
            BTreeSet::from(["/usr".to_owned(), "/var/lib/thing".to_owned()])
        );
    }

    #[test]
    fn plain_fstab_mounts_are_not_expected() {
        let fstab = "/dev/sda1 / ext4 defaults 0 1\n/dev/sda2 /home ext4 defaults 0 2\n";
        assert!(expected_nested_mounts(&parse_fstab(fstab)).is_empty());
    }

    #[test]
    fn missing_expected_mounts_are_reported() {
        let mounts = [
            "/sysroot".to_owned(),
            "/sysroot/usr".to_owned(),
            "/sysroot/var/lib/thing".to_owned(),
        ];
        let fstab = parse_fstab(
            "/dev/sda1 / ext4 defaults 0 1\n\
             /dev/sda2 /usr ext4 defaults 0 2\n\
             /dev/sda3 /var ext4 defaults,x-initrd.mount 0 2\n\
             /dev/sda4 /var/lib/thing ext4 defaults,x-initrd.mount 0 2\n",
        );
        // /sysroot/usr and /sysroot/var/lib/thing are mounted; /sysroot/var
        // is not.
        assert_eq!(
            missing_expected_mounts("/sysroot", &mounts, &fstab),
            ["/sysroot/var".to_owned()]
        );
        // With everything mounted, nothing is missing.
        let mounts = [
            "/sysroot".to_owned(),
            "/sysroot/usr".to_owned(),
            "/sysroot/var".to_owned(),
            "/sysroot/var/lib/thing".to_owned(),
        ];
        assert!(missing_expected_mounts("/sysroot", &mounts, &fstab).is_empty());
    }

    #[test]
    fn octal_escapes_decode() {
        assert_eq!(unescape("plain"), "plain");
        assert_eq!(unescape("a\\040b"), "a b");
        assert_eq!(unescape("a\\011b"), "a\tb");
        assert_eq!(unescape("a\\012b"), "a\nb");
        assert_eq!(unescape("a\\134b"), "a\\b");
        // Not octal: left alone.
        assert_eq!(unescape("a\\08b"), "a\\08b");
        // Beyond a byte: left alone.
        assert_eq!(unescape("a\\777b"), "a\\777b");
        // Truncated escape: left alone.
        assert_eq!(unescape("a\\04"), "a\\04");
    }
}
