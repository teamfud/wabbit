//! Compile-time white-labeling: every brand-bearing string in the shipped
//! binaries derives from these constants.
//!
//! A white-label build sets any of these environment variables before
//! building the workspace; the defaults reproduce the stock names, so an
//! ordinary build behaves exactly as it always has.
//!
//! | variable | default | governs |
//! | --- | --- | --- |
//! | `WABBIT_BRAND_NAME` | `wabbit` | the product name: `argv[0]`, the cgroup, the IPC socket, the CLI flags (`--<name>-namespace`, `--<name>-verify-*`, `--<name>-watchdog`), the in-image binary path, the installer's paths, and the wording of messages that name the product |
//! | `WABBIT_BRAND_ENV_PREFIX` | `WABBIT` | the environment variables: `<prefix>_IPC_SOCKET`, `<prefix>_FILESYSTEM_CONFIGURATION_FILE`, `<prefix>_SIGN_DIR` |
//! | `WABBIT_BRAND_SIGN_NAME` | `bnuuy` | the boot sign's file name (`<name>.bin`) and the wording that names the protections |
//! | `WABBIT_BRAND_SIGN_MAGIC` | `BNUY` | the sign's magic, exactly four bytes |
//! | `WABBIT_INSTALL_CLIENT_NAME` | `wabbit-ipc` | the IPC client's *installed* file name: the installer writes it to the box's `/usr/local/bin`, and the deployment generator's `--name-ipc` sets it so the box's client and the deployment directory's copy answer to the same name — and so the client's own help text names itself. The value itself is read by the installer (`wabbit-install`), which — unlike this `no_std` crate — can allocate; this crate only validates it. |
//! | `WABBIT_POLICY_CLI_NAME` | `wabbit-policy` | the signing/inspection CLI's file name, as the deployment generator's `--name-policy` sets it: other binaries' help text names that tool by it (`<cli> gen-key`, `<cli> inspect`) |
//!
//! The values are validated at compile time — each must be a single
//! path- and shell-safe component (ASCII alphanumerics plus `-`, `_`,
//! `.`), and the magic exactly four bytes — so a typo fails the build
//! instead of producing a half-branded binary.
//!
//! These constants are read at the point of use, so a branded build
//! needs only the environment variables: no source changes.
//! `vm/generate-deployment.sh --brand-name` (and the other `--brand-*`
//! flags) exports them for a whole deployment build. The crate
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

/// The IPC client's *installed* file name: the one the installer writes to
/// the box's `/usr/local/bin`, and the one the client's own help text
/// answers to. The deployment generator's `--name-ipc` sets it (through
/// `WABBIT_INSTALL_CLIENT_NAME`) so the box's client and the deployment
/// directory's copy answer to the same name.
pub const CLIENT_NAME: &str = match option_env!("WABBIT_INSTALL_CLIENT_NAME") {
    Some(name) => name,
    None => "wabbit-ipc",
};

/// The signing/inspection CLI's file name, as the deployment generator's
/// `--name-policy` sets it (through `WABBIT_POLICY_CLI_NAME`): other
/// binaries' help text names that tool by it.
pub const POLICY_NAME: &str = match option_env!("WABBIT_POLICY_CLI_NAME") {
    Some(name) => name,
    None => "wabbit-policy",
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
    match option_env!("WABBIT_INSTALL_CLIENT_NAME") {
        Some(client_name) => {
            assert!(
                !client_name.is_empty(),
                "WABBIT_INSTALL_CLIENT_NAME must not be empty"
            );
            assert!(
                is_safe_component(client_name),
                "WABBIT_INSTALL_CLIENT_NAME must be one path- and shell-safe \
                 component (ASCII alphanumerics, '-', '_', '.')"
            );
        }
        None => {}
    }
    match option_env!("WABBIT_POLICY_CLI_NAME") {
        Some(policy_name) => {
            assert!(
                !policy_name.is_empty(),
                "WABBIT_POLICY_CLI_NAME must not be empty"
            );
            assert!(
                is_safe_component(policy_name),
                "WABBIT_POLICY_CLI_NAME must be one path- and shell-safe \
                 component (ASCII alphanumerics, '-', '_', '.')"
            );
        }
        None => {}
    }
};
