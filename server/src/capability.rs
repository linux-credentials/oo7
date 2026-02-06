use rustix::{
    mm::{MlockAllFlags, mlockall},
    process::{Gid, Uid, getgid, getuid},
    thread::{
        CapabilitySet, CapabilitySets, capabilities, remove_capability_from_bounding_set,
        set_capabilities,
    },
};

// libc wrappers since rustix doesn't expose these in public API
fn setresuid(ruid: Uid, euid: Uid, suid: Uid) -> Result<(), rustix::io::Errno> {
    let ret = unsafe { libc::setresuid(ruid.as_raw(), euid.as_raw(), suid.as_raw()) };
    if ret == 0 {
        Ok(())
    } else {
        Err(rustix::io::Errno::from_raw_os_error(
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EINVAL),
        ))
    }
}

fn setresgid(rgid: Gid, egid: Gid, sgid: Gid) -> Result<(), rustix::io::Errno> {
    let ret = unsafe { libc::setresgid(rgid.as_raw(), egid.as_raw(), sgid.as_raw()) };
    if ret == 0 {
        Ok(())
    } else {
        Err(rustix::io::Errno::from_raw_os_error(
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EINVAL),
        ))
    }
}

fn setgroups(groups: &[Gid]) -> Result<(), rustix::io::Errno> {
    let gids: Vec<libc::gid_t> = groups.iter().map(|g| g.as_raw()).collect();
    let ret = unsafe { libc::setgroups(gids.len(), gids.as_ptr()) };
    if ret == 0 {
        Ok(())
    } else {
        Err(rustix::io::Errno::from_raw_os_error(
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EINVAL),
        ))
    }
}

fn set_bounding_set(caps: CapabilitySet) -> Result<(), rustix::io::Errno> {
    let caps_to_drop = CapabilitySet::all().difference(caps);
    for cap in caps_to_drop.iter() {
        let _ = remove_capability_from_bounding_set(cap);
    }
    Ok(())
}

#[derive(Debug, PartialEq)]
enum CapabilityState {
    Full,    // setuid root or root user
    Partial, // filesystem-based capabilities
    None,
}

pub fn drop_unnecessary_capabilities() -> Result<(), rustix::io::Errno> {
    // Abort if we can't read capabilities (libcap-ng CAPNG_FAIL behavior)
    let caps = capabilities(None).unwrap_or_else(|e| {
        tracing::error!("Error getting process capabilities: {:?}, aborting", e);
        std::process::exit(1);
    });

    let capability_state = {
        if caps.permitted.is_empty() && caps.effective.is_empty() {
            CapabilityState::None
        } else {
            let all_caps = caps.effective | caps.permitted | caps.inheritable;
            // 10+ capabilities = Full (matches libcap-ng heuristic)
            if all_caps.bits().count_ones() >= 10 {
                CapabilityState::Full
            } else {
                CapabilityState::Partial
            }
        }
    };

    match capability_state {
        CapabilityState::Full => {
            set_capabilities(
                None,
                CapabilitySets {
                    effective: CapabilitySet::IPC_LOCK,
                    permitted: CapabilitySet::IPC_LOCK,
                    inheritable: CapabilitySet::empty(),
                },
            )?;

            // Needed so permitted caps survive uid 0 → non-zero transition
            if unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) } != 0 {
                tracing::warn!("Failed to set PR_SET_KEEPCAPS");
            }

            if let Err(err) = set_bounding_set(CapabilitySet::IPC_LOCK) {
                tracing::debug!("Could not set bounding set (may not be supported): {}", err);
            }

            let uid = getuid();
            let gid = getgid();

            setresgid(gid, gid, gid)?;
            setgroups(&[])?;
            setresuid(uid, uid, uid)?; // Clears effective caps despite keepcaps

            if unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0) } != 0 {
                tracing::warn!("Failed to clear PR_SET_KEEPCAPS");
            }

            // Re-raise from permitted → effective
            set_capabilities(
                None,
                CapabilitySets {
                    effective: CapabilitySet::IPC_LOCK,
                    permitted: CapabilitySet::IPC_LOCK,
                    inheritable: CapabilitySet::empty(),
                },
            )?;
        }
        CapabilityState::None => {
            tracing::warn!("No process capabilities, insecure memory might get used");
            return Ok(());
        }
        CapabilityState::Partial => {
            if !caps.effective.contains(CapabilitySet::IPC_LOCK) {
                tracing::warn!("Insufficient process capabilities, insecure memory might get used");
            }

            // Clear bounding set if we have CAP_SETPCAP (do this before dropping caps)
            if caps.effective.contains(CapabilitySet::SETPCAP)
                && let Err(err) = set_bounding_set(CapabilitySet::IPC_LOCK)
            {
                tracing::warn!("Failed to set bounding set: {}", err);
            }

            set_capabilities(
                None,
                CapabilitySets {
                    effective: CapabilitySet::IPC_LOCK,
                    permitted: CapabilitySet::IPC_LOCK,
                    inheritable: CapabilitySet::empty(),
                },
            )?;
        }
    }

    // After dropping capabilities, try to lock memory
    // This prevents secrets from being swapped to disk
    match mlockall(MlockAllFlags::CURRENT | MlockAllFlags::FUTURE) {
        Ok(_) => {
            tracing::info!("Successfully locked all memory pages");
        }
        Err(e) => {
            tracing::warn!(
                "Failed to lock memory pages (secrets may be swapped to disk): {}",
                e
            );
        }
    }

    Ok(())
}
