use std::fs;
use std::io::{self, ErrorKind};
use std::path::PathBuf;

/// Returns the path to the PID file.
pub fn pid_file_path() -> PathBuf {
    crate::grob_home()
        .unwrap_or_else(|| PathBuf::from(".grob"))
        .join("grob.pid")
}

/// Writes the current process PID to the PID file.
///
/// # Errors
///
/// Returns an [`io::Error`] if the parent directory cannot be created or the
/// PID file cannot be written.
pub fn write_pid() -> io::Result<()> {
    let pid_file = pid_file_path();

    // Create parent directory if it doesn't exist
    if let Some(parent) = pid_file.parent() {
        fs::create_dir_all(parent)?;
    }

    let pid = std::process::id();
    fs::write(&pid_file, pid.to_string())?;
    tracing::info!("PID {} written to {:?}", pid, pid_file);
    Ok(())
}

/// Reads the PID from the PID file.
///
/// # Errors
///
/// Returns an [`io::Error`] if the PID file cannot be read, or
/// [`ErrorKind::InvalidData`] if its contents do not parse as a `u32`.
pub fn read_pid() -> io::Result<u32> {
    let pid_file = pid_file_path();
    let pid_str = fs::read_to_string(&pid_file)?;
    pid_str
        .trim()
        .parse::<u32>()
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))
}

/// Removes the PID file.
///
/// # Errors
///
/// Returns an [`io::Error`] if the PID file exists but cannot be removed.
pub fn cleanup_pid() -> io::Result<()> {
    let pid_file = pid_file_path();
    if pid_file.exists() {
        fs::remove_file(&pid_file)?;
        tracing::info!("PID file removed: {:?}", pid_file);
    }
    Ok(())
}

/// Check if a grob process is running at the given PID.
/// On Linux, additionally verifies via /proc that the process is actually grob
/// (guards against stale PID files after PID reuse).
#[cfg(feature = "unix-signals")]
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

/// Fallback when nix is unavailable: only our own PID is considered valid.
#[cfg(all(unix, not(feature = "unix-signals")))]
pub fn is_process_running(pid: u32) -> bool {
    pid == std::process::id()
}

/// Checks if a process with the given PID exists via tasklist.
#[cfg(windows)]
pub fn is_process_running(pid: u32) -> bool {
    match std::process::Command::new("tasklist")
        .args(["/FI", &format!("PID eq {}", pid), "/NH"])
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            !stdout.contains("No tasks")
        }
        Err(_) => false,
    }
}
