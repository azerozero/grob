use std::fs;
use std::io::{self, ErrorKind};
use std::path::PathBuf;

/// Get the PID file path
pub fn get_pid_file() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".grob").join("grob.pid")
}

/// Write the current process PID to the PID file
pub fn write_pid() -> io::Result<()> {
    let pid_file = get_pid_file();

    // Create parent directory if it doesn't exist
    if let Some(parent) = pid_file.parent() {
        fs::create_dir_all(parent)?;
    }

    let pid = std::process::id();
    fs::write(&pid_file, pid.to_string())?;
    tracing::info!("PID {} written to {:?}", pid, pid_file);
    Ok(())
}

/// Read the PID from the PID file
pub fn read_pid() -> io::Result<u32> {
    let pid_file = get_pid_file();
    let pid_str = fs::read_to_string(&pid_file)?;
    pid_str
        .trim()
        .parse::<u32>()
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))
}

/// Remove the PID file
pub fn cleanup_pid() -> io::Result<()> {
    let pid_file = get_pid_file();
    if pid_file.exists() {
        fs::remove_file(&pid_file)?;
        tracing::info!("PID file removed: {:?}", pid_file);
    }
    Ok(())
}

/// Check if a grob process is running at the given PID.
/// On Linux, additionally verifies via /proc that the process is actually grob
/// (guards against stale PID files after PID reuse).
pub fn is_process_running(pid: u32) -> bool {
    use nix::sys::signal::kill;
    use nix::unistd::Pid;

    // Signal 0 (None) checks process existence without side effects
    if kill(Pid::from_raw(pid as i32), None).is_err() {
        return false;
    }

    // On Linux, verify cmdline contains "grob" to detect PID reuse
    #[cfg(target_os = "linux")]
    {
        let cmdline_path = format!("/proc/{}/cmdline", pid);
        if let Ok(cmdline) = fs::read(&cmdline_path) {
            // /proc/*/cmdline uses NUL separators; convert to readable string
            let cmdline_str = String::from_utf8_lossy(&cmdline);
            if !cmdline_str.contains("grob") {
                return false;
            }
        }
    }

    true
}
