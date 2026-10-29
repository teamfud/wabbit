use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    // The white-label knobs (src/brand.rs): changing one must rebuild every
    // crate that derives a name from it.
    println!("cargo:rerun-if-env-changed=WABBIT_BRAND_NAME");
    println!("cargo:rerun-if-env-changed=WABBIT_BRAND_ENV_PREFIX");
    println!("cargo:rerun-if-env-changed=WABBIT_BRAND_SIGN_NAME");
    println!("cargo:rerun-if-env-changed=WABBIT_BRAND_SIGN_MAGIC");

    let build_time = std::env::var("SOURCE_DATE_EPOCH").unwrap_or_else(|_| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is before the Unix epoch")
            .as_secs()
            .to_string()
    });

    println!("cargo:rustc-env=WABBIT_BUILD_TIME={build_time}");
}
