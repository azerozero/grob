//! Opt-in process memory hardening, applied before credentials and runtime startup.
//!
//! These controls prevent ordinary core dumps and optionally swapping. They do
//! not encrypt RAM or protect against a compromised kernel or privileged debugger.

use anyhow::{Context, Result};

/// Selects process-wide memory exposure controls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryHardening {
    /// Leaves the operating system's memory policy unchanged.
    Off,
    /// Disables core dumps and, on Linux, unprivileged process inspection.
    NoDump,
    /// Also locks current and future mappings into RAM on Linux.
    Locked,
}

impl std::str::FromStr for MemoryHardening {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "off" => Ok(Self::Off),
            "no-dump" => Ok(Self::NoDump),
            "locked" => Ok(Self::Locked),
            _ => anyhow::bail!("GROB_MEMORY_HARDENING must be off, no-dump, or locked"),
        }
    }
}

/// Applies the requested policy before loading secrets or creating runtime threads.
///
/// Reads `GROB_MEMORY_HARDENING`. An absent variable leaves the OS policy unchanged.
/// A requested protection must succeed; there is no silent downgrade.
///
/// # Errors
/// Returns an error for invalid modes, unsupported platforms, or rejected OS calls.
pub fn harden_from_env() -> Result<()> {
    let mode = match std::env::var("GROB_MEMORY_HARDENING") {
        Ok(value) => value.parse()?,
        Err(std::env::VarError::NotPresent) => MemoryHardening::Off,
        Err(error) => return Err(error).context("Invalid memory hardening setting"),
    };
    apply(mode)
}

/// Applies irreversible process controls for the lifetime of the current process.
///
/// Call before loading credentials. `Locked` requires Linux and enough memlock
/// allowance for peak virtual memory; later allocation failure remains possible.
/// Core limits also affect child commands; memory locks do not survive exec.
///
/// # Errors
/// Returns an error if any requested control cannot be established.
pub fn apply(mode: MemoryHardening) -> Result<()> {
    if mode == MemoryHardening::Off {
        return Ok(());
    }
    #[cfg(not(target_os = "linux"))]
    anyhow::ensure!(
        mode != MemoryHardening::Locked,
        "Locked memory mode requires Linux"
    );
    #[cfg(unix)]
    {
        disable_dumps()?;
        #[cfg(target_os = "linux")]
        if mode == MemoryHardening::Locked {
            lock_memory()?;
        }
        Ok(())
    }
    #[cfg(not(unix))]
    anyhow::bail!("Memory hardening requires a supported Unix host")
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn disable_dumps() -> Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: The pointer refers to an initialized rlimit for the duration of the syscall.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0 {
        return Err(std::io::Error::last_os_error()).context("Cannot disable core dumps");
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: PR_SET_DUMPABLE takes integer arguments and dereferences no pointers.
        if unsafe {
            libc::prctl(
                libc::PR_SET_DUMPABLE,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error()).context("Cannot disable process dumps");
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn lock_memory() -> Result<()> {
    // SAFETY: mlockall operates on the calling process and takes no pointers.
    if unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) } != 0 {
        return Err(std::io::Error::last_os_error()).context(
            "Cannot lock process memory; configure RLIMIT_MEMLOCK for peak virtual memory",
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unrecognized_modes() {
        for mode in ["", "true", "1", "encrypted", "locked "] {
            assert!(mode.parse::<MemoryHardening>().is_err());
        }
    }

    #[test]
    #[allow(unsafe_code)]
    fn child() {
        let Ok(mode) = std::env::var("GROB_TEST_MEMORY_MODE") else {
            return;
        };
        let mode: MemoryHardening = mode.parse().unwrap();
        #[cfg(target_os = "linux")]
        if mode == MemoryHardening::Locked {
            let limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: The initialized limit lives through the syscall in this child only.
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) }, 0);
            assert!(
                apply(mode).is_err(),
                "insufficient memlock must fail closed"
            );
            return;
        }
        #[cfg(unix)]
        {
            apply(mode).unwrap();
            let mut limit = libc::rlimit {
                rlim_cur: 1,
                rlim_max: 1,
            };
            // SAFETY: getrlimit writes into an initialized, valid rlimit pointer.
            assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) }, 0);
            assert_eq!((limit.rlim_cur, limit.rlim_max), (0, 0));
            #[cfg(target_os = "linux")]
            // SAFETY: PR_GET_DUMPABLE takes no pointer arguments.
            assert_eq!(
                unsafe {
                    libc::prctl(
                        libc::PR_GET_DUMPABLE,
                        0 as libc::c_ulong,
                        0 as libc::c_ulong,
                        0 as libc::c_ulong,
                        0 as libc::c_ulong,
                    )
                },
                0
            );
        }
        #[cfg(not(unix))]
        assert!(apply(mode).is_err());
    }

    #[test]
    fn process_policy_is_enforced_in_isolated_children() {
        let modes = if cfg!(target_os = "linux") {
            vec!["no-dump", "locked"]
        } else {
            vec!["no-dump"]
        };
        for mode in modes {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "security::memory::tests::child", "--nocapture"])
                .env("GROB_TEST_MEMORY_MODE", mode)
                .status()
                .unwrap();
            assert!(status.success());
        }
        #[cfg(not(target_os = "linux"))]
        assert!(apply(MemoryHardening::Locked).is_err());
    }
}
