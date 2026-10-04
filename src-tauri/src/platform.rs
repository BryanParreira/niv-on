//! OS-specific start-up and capability checks.
//!
//! Windows: `wpcap.dll` ships with Npcap in `%SystemRoot%\System32\Npcap`,
//! which is not on the default DLL search path. The binary delay-loads it
//! (see build.rs), so Niv.ON starts even without Npcap; we add the Npcap
//! directory at start-up and refuse pcap calls with a helpful message when
//! the DLL is missing instead of crashing.

#[cfg(windows)]
fn npcap_dir() -> std::path::PathBuf {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    std::path::Path::new(&root).join("System32").join("Npcap")
}

pub fn init() {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        #[link(name = "kernel32")]
        extern "system" {
            fn SetDllDirectoryW(path: *const u16) -> i32;
        }
        let wide: Vec<u16> = npcap_dir().as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        // SAFETY: valid NUL-terminated UTF-16 string that outlives the call.
        unsafe {
            SetDllDirectoryW(wide.as_ptr());
        }
    }
}

/// Ok when libpcap/Npcap can be used on this machine.
pub fn pcap_available() -> Result<(), String> {
    #[cfg(windows)]
    {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let legacy = std::path::Path::new(&root).join("System32").join("wpcap.dll");
        if !npcap_dir().join("wpcap.dll").exists() && !legacy.exists() {
            return Err("Npcap is not installed. Download it from https://npcap.com (tick \"Support raw 802.11 traffic\" for monitor mode), then restart Niv.ON. The simulator works without it.".into());
        }
    }
    Ok(())
}
