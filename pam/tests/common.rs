use std::{
    ffi::CStr,
    fs,
    io::{self, Read},
    os::{
        fd::{AsRawFd, OwnedFd, RawFd},
        unix::{fs::symlink, net::UnixStream},
    },
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

pub const WAIT: Duration = Duration::from_secs(5);

pub struct Artifacts {
    pub module: PathBuf,
    pub tokens: PathBuf,
    pub caller: PathBuf,
}

impl Artifacts {
    pub fn discover() -> io::Result<Self> {
        let executable = std::env::current_exe()?;
        let directory = executable.parent().expect("test executable has a parent");
        let examples = directory
            .parent()
            .expect("test executable has a profile directory")
            .join("examples");
        let module = directory.join("libpam_oo7.so");
        let tokens = examples.join("libpam_test_tokens.so");
        let caller = examples.join("pam_caller");
        for path in [&module, &tokens, &caller] {
            if !path.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "missing {}; run cargo test -p oo7-pam to build the fixtures",
                        path.display()
                    ),
                ));
            }
        }
        Ok(Self {
            module,
            tokens,
            caller,
        })
    }
}

pub struct Fixture {
    pub directory: tempfile::TempDir,
    pub socket_path: PathBuf,
    caller: PathBuf,
}

impl Fixture {
    pub fn new(artifacts: &Artifacts) -> io::Result<Self> {
        // Keep socket paths short and PAM module paths free of spaces.
        let directory = tempfile::Builder::new()
            .prefix("oo7-pam-")
            .tempdir_in("/tmp")?;
        let module = directory.path().join("pam_oo7.so");
        let tokens = directory.path().join("pam_test_tokens.so");
        symlink(&artifacts.module, &module)?;
        symlink(&artifacts.tokens, &tokens)?;
        fs::write(
            directory.path().join("oo7-test"),
            format!(
                "auth required {tokens}\nauth required {module}\n\
                 session required {module}\npassword required {tokens}\n\
                 password required {module}\n",
                module = module.display(),
                tokens = tokens.display(),
            ),
        )?;
        let socket_path = directory.path().join("daemon.sock");
        Ok(Self {
            directory,
            socket_path,
            caller: artifacts.caller.clone(),
        })
    }

    pub fn caller_command(&self, operation: &str) -> Command {
        let mut command = Command::new(&self.caller);
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.directory.path())
            .env("XDG_RUNTIME_DIR", self.directory.path())
            .env("OO7_PAM_SOCKET", &self.socket_path)
            .env("OO7_PAM_TEST_CONFIG", self.directory.path())
            .env("OO7_PAM_TEST_OPERATION", operation);
        command
    }
}

pub struct Caller {
    pub control: UnixStream,
    process: Child,
}

impl Caller {
    pub fn spawn(mut command: Command) -> io::Result<Self> {
        let (control, child_control) = UnixStream::pair()?;
        let child_control: OwnedFd = child_control.into();
        let process = command
            .stdin(Stdio::from(child_control))
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?;
        Ok(Self { control, process })
    }

    pub fn wait_calling(&mut self) -> io::Result<()> {
        self.expect_marker("calling", WAIT)
    }

    pub fn expect_marker(&mut self, expected: &str, timeout: Duration) -> io::Result<()> {
        let deadline = Instant::now() + timeout;
        let mut marker = Vec::new();
        loop {
            self.control.set_read_timeout(Some(remaining(deadline)?))?;
            let mut byte = [0];
            self.control.read_exact(&mut byte)?;
            if byte[0] == b'\n' {
                break;
            }
            marker.push(byte[0]);
            if marker.len() > 128 {
                return Err(io::Error::other("caller sent an oversized marker"));
            }
        }
        if marker != expected.as_bytes() {
            return Err(io::Error::other(format!(
                "expected caller marker {expected:?}, received {:?}",
                String::from_utf8_lossy(&marker)
            )));
        }
        Ok(())
    }

    pub fn assert_pending(&self, peer: RawFd, timeout: Duration) -> io::Result<()> {
        let mut descriptors = [
            libc::pollfd {
                fd: self.control.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: peer,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        poll(&mut descriptors, timeout)?;
        if descriptors[0].revents != 0 {
            return Err(io::Error::other("PAM returned before the daemon response"));
        }
        if descriptors[1].revents == 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "PAM did not send a request",
            ));
        }
        Ok(())
    }

    pub fn assert_blocked(&self, timeout: Duration) -> io::Result<()> {
        let mut descriptors = [libc::pollfd {
            fd: self.control.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }];
        poll(&mut descriptors, timeout)?;
        if descriptors[0].revents != 0 {
            return Err(io::Error::other(
                "PAM returned while its request was awaiting a response",
            ));
        }
        Ok(())
    }

    pub fn wait_success(&mut self, timeout: Duration) -> io::Result<()> {
        let deadline = Instant::now() + timeout;
        self.expect_marker("returned 0", remaining(deadline)?)?;
        self.wait_exit_success(remaining(deadline)?)
    }

    pub fn wait_exit_success(&mut self, timeout: Duration) -> io::Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.process.try_wait()? {
                return if status.success() {
                    Ok(())
                } else {
                    Err(io::Error::other(format!("PAM caller exited with {status}")))
                };
            }
            std::thread::sleep(remaining(deadline)?.min(Duration::from_millis(10)));
        }
    }
}

impl Drop for Caller {
    fn drop(&mut self) {
        // Reap the process even after a failed assertion or a timeout.
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "PAM test timed out"))
}

fn poll(descriptors: &mut [libc::pollfd], timeout: Duration) -> io::Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let milliseconds = remaining(deadline)?.as_millis().max(1);
        // The descriptors remain valid for the duration of this call.
        let result = unsafe {
            libc::poll(
                descriptors.as_mut_ptr(),
                descriptors.len() as libc::nfds_t,
                milliseconds.min(i32::MAX as u128) as i32,
            )
        };
        if result >= 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

pub fn current_username() -> io::Result<String> {
    let mut buffer = vec![0; 1024];
    loop {
        let mut entry = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut result = std::ptr::null_mut();
        // All output storage is local so parallel tests cannot race NSS's
        // non-reentrant getpwuid buffer.
        let status = unsafe {
            libc::getpwuid_r(
                libc::getuid(),
                entry.as_mut_ptr(),
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut result,
            )
        };
        if status == libc::ERANGE {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status));
        }
        if result.is_null() {
            return Err(io::Error::other("current user has no passwd entry"));
        }
        // A successful lookup points into entry and the live buffer.
        return Ok(unsafe { CStr::from_ptr((*result).pw_name) }
            .to_string_lossy()
            .into_owned());
    }
}
