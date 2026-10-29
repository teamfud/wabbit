/// The trusted Ed25519 public key for policy files, as hex or base64.
///
/// Compile-time overridable (`WABBIT_POLICY_PUBLIC_KEY`), the same
/// white-label pattern as the brand knobs: a custom deployment builds
/// with its own key so its wabbit only ever trusts its own policies.
pub const POLICY_PUBLIC_KEY: &str = match option_env!("WABBIT_POLICY_PUBLIC_KEY") {
    Some(key) => key,
    None => "d6ffc2cf7945252894cef125e91c9547d7204da4fc0d2ef84c31df78a9bcee9a",
};

/// Every trusted policy-signing public key, as `(key id, key)` pairs in
/// preference order. The key id travels in the policy header (WSPF v4),
/// so a policy signed with a rotated key is named — a v3-era binary
/// rejects it, and the header says *which* key would have been needed.
///
/// New keys are appended with the next id and a rebuild; the env override
/// replaces id 0.
pub const POLICY_PUBLIC_KEYS: &[(u8, &str)] = &[(0, POLICY_PUBLIC_KEY)];

/// Unix timestamp when the shared wabbit metadata was built.
pub const BUILD_TIME: &str = env!("WABBIT_BUILD_TIME");
