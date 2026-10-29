//! Compile-time white-labeling: every brand-bearing string in the shipped
//! binaries derives from these constants.
//!
//! A white-label build sets any of four environment variables before
//! building the workspace; the defaults reproduce the stock names, so an
//! ordinary build behaves exactly as it always has.
//!
//! | variable | default | governs |
//! | --- | --- | --- |
//! | `WABBIT_BRAND_NAME` | `wabbit` | the product name: `argv[0]`, the cgroup, the IPC socket, the CLI flags (`--<name>-namespace`, `--<name>-verify-*`, `--<name>-watchdog`), the in-image binary path, the installer's paths, and the wording of messages that name the product |
//! | `WABBIT_BRAND_ENV_PREFIX` | `WABBIT` | the environment variables: `<prefix>_IPC_SOCKET`, `<prefix>_FILESYSTEM_CONFIGURATION_FILE`, `<prefix>_SIGN_DIR` |
//! | `WABBIT_BRAND_SIGN_NAME` | `bnuuy` | the boot sign's file name (`<name>.bin`) and the wording that names the protections |
//! | `WABBIT_BRAND_SIGN_MAGIC` | `BNUY` | the sign's magic, exactly four bytes |
//!
//! The values are validated at compile time — each must be a single
//! path- and shell-safe component (ASCII alphanumerics plus `-`, `_`,
//! `.`), and the magic exactly four bytes — so a typo fails the build
//! instead of producing a half-branded binary.
//!
//! These constants are read at the point of use, so a branded build
//! needs only the environment variables: no source changes. The crate
//! names themselves stay (the `log` crate bakes `module_path!()` into
//! every call site, and a crate name cannot be parameterized by an
//! environment variable), so a `strings` audit of a branded binary still
//! shows the internal log-target literals; the console output does not.

/// The product name, as a single path/shell-safe component.
pub const NAME: &str = match option_env!("WABBIT_BRAND_NAME") {
    Some(name) => name,
    None => "wabbit",
};

/// The prefix of the environment variables the binaries exchange.
pub const ENV_PREFIX: &str = match option_env!("WABBIT_BRAND_ENV_PREFIX") {
    Some(prefix) => prefix,
    None => "WABBIT",
};

/// The name of the boot sign: `<name>.bin` in the sign directory.
pub const SIGN_NAME: &str = match option_env!("WABBIT_BRAND_SIGN_NAME") {
    Some(name) => name,
    None => "bnuuy",
};

/// The boot sign's magic: exactly four bytes.
pub const SIGN_MAGIC: &str = match option_env!("WABBIT_BRAND_SIGN_MAGIC") {
    Some(magic) => magic,
    None => "BNUY",
};

/// Whether `value` consists only of ASCII alphanumerics and `-`, `_`,
/// `.` — safe as a path component, an `argv` string, a shell word, and
/// an environment-variable name.
const fn is_safe_component(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let byte = bytes[i];
        if !(byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.') {
            return false;
        }
        i += 1;
    }
    true
}

// The compile-time gate: every branded build everywhere in the workspace
// (this crate is a dependency of all of them) refuses a value that would
// leak into a path, an `argv`, a shell snippet, or an environment name
// in a form that breaks or betrays it.
const _: () = {
    assert!(!NAME.is_empty(), "WABBIT_BRAND_NAME must not be empty");
    assert!(
        is_safe_component(NAME),
        "WABBIT_BRAND_NAME must be one path- and shell-safe component \
         (ASCII alphanumerics, '-', '_', '.')"
    );
    assert!(
        !ENV_PREFIX.is_empty(),
        "WABBIT_BRAND_ENV_PREFIX must not be empty"
    );
    assert!(
        is_safe_component(ENV_PREFIX),
        "WABBIT_BRAND_ENV_PREFIX must be one shell-safe component"
    );
    assert!(
        !SIGN_NAME.is_empty(),
        "WABBIT_BRAND_SIGN_NAME must not be empty"
    );
    assert!(
        is_safe_component(SIGN_NAME),
        "WABBIT_BRAND_SIGN_NAME must be one path- and shell-safe component"
    );
    assert!(
        SIGN_MAGIC.len() == 4,
        "WABBIT_BRAND_SIGN_MAGIC must be exactly four bytes"
    );
    assert!(
        is_safe_component(SIGN_MAGIC),
        "WABBIT_BRAND_SIGN_MAGIC must be four printable bytes"
    );
};
