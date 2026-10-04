fn main() {
    // Windows: delay-load Npcap's wpcap.dll so the app still starts (and can
    // explain how to install Npcap) on machines without it.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc")
    {
        println!("cargo:rustc-link-arg=/DELAYLOAD:wpcap.dll");
        println!("cargo:rustc-link-lib=delayimp");
    }
    tauri_build::build()
}
