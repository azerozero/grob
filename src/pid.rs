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

/// Check if a process is running
pub fn is_process_running(pid: u32) -> bool {
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;

    kill(Pid::from_raw(pid as i32), Signal::SIGCONT).is_ok()
}
