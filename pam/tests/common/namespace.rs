//! Runs privileged PAM tests in a fresh process with private namespaces.

use std::{
    env, fs,
    io::{self, Read, Seek, SeekFrom},
    os::unix::fs::PermissionsExt,
    path::Path,
    process::Command,
    thread,
    time::{Duration, Instant},
};

const INSIDE_ENV: &str = "OO7_PAM_TEST_INSIDE";

pub fn run(test_name: &str, test: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
    if env::var("OO7_PAM_PRIVILEGED_TESTS").as_deref() != Ok("1") || unsafe { libc::geteuid() } != 0
    {
        return Err(io::Error::other(
            "privileged PAM tests require OO7_PAM_PRIVILEGED_TESTS=1 and a root Cargo test runner; build artifacts without privileges",
        ));
    }
    if env::var(INSIDE_ENV).as_deref() == Ok("1") {
        test()
    } else {
        run_namespace(test_name)
    }
}

fn run_namespace(test_name: &str) -> io::Result<()> {
    let executable = env::current_exe()?;
    let deps = executable.parent().unwrap();
    let fixtures = tempfile::tempdir()?;
    // Keep sandbox paths short and independent of the host's temporary
    // directory.
    let root = Path::new("/run").join(fixtures.path().file_name().unwrap());
    let worker = root.join("deps").join(executable.file_name().unwrap());
    for (name, contents) in [
        (
            "passwd",
            "root:x:0:0:root:/root:/bin/false\noo7-test:x:65534:65534:fixture:/:/bin/false\n",
        ),
        ("group", "root:x:0:\noo7-test:x:65534:\n"),
        ("nsswitch.conf", "passwd: files\ngroup: files\n"),
    ] {
        let path = fixtures.path().join(name);
        fs::write(&path, contents)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o444))?;
    }

    let mut command = Command::new("bwrap");
    command.env_clear().env("PATH", "/usr/bin:/bin").args([
        "--die-with-parent",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-uts",
        "--ro-bind",
        "/",
        "/",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/run",
        "--tmpfs",
        "/home",
        "--tmpfs",
        "/root",
        "--clearenv",
        "--setenv",
        "PATH",
        "/usr/bin:/bin",
        "--setenv",
        "OO7_PAM_PRIVILEGED_TESTS",
        "1",
        "--setenv",
        INSIDE_ENV,
        "1",
        "--cap-add",
        "CAP_SETUID",
        "--cap-add",
        "CAP_SETGID",
        "--cap-add",
        "CAP_CHOWN",
    ]);
    command
        .arg("--tmpfs")
        .arg(env::temp_dir().canonicalize()?)
        .args(["--perms", "0755", "--dir"])
        .arg(&root)
        .args(["--setenv", "TMPDIR"])
        .arg(&root)
        .arg("--chdir")
        .arg(&root);
    for (source, destination) in [
        (deps.to_owned(), root.join("deps")),
        (
            deps.parent().unwrap().join("examples"),
            root.join("examples"),
        ),
    ] {
        command
            .arg("--ro-bind")
            .arg(source.canonicalize()?)
            .arg(destination);
    }
    for name in ["passwd", "group", "nsswitch.conf"] {
        command
            .arg("--ro-bind")
            .arg(fixtures.path().join(name))
            .arg(format!("/etc/{name}"));
    }

    // File output avoids pipe backpressure while the parent polls the child.
    let mut output = tempfile::tempfile()?;
    let mut child = command
        .arg(worker)
        .args([
            "--exact",
            test_name,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .stdout(output.try_clone()?)
        .stderr(output.try_clone()?)
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(120);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            result => {
                let _ = child.kill();
                child.wait()?;
                break Err(result.err().unwrap_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "isolated PAM test exceeded 120 seconds",
                    )
                }));
            }
        }
    };
    output.seek(SeekFrom::Start(0))?;
    let mut text = String::new();
    output.read_to_string(&mut text)?;
    let status =
        status.map_err(|error| io::Error::new(error.kind(), format!("{error}\n{text}")))?;
    if !status.success() || !text.contains("1 passed; 0 failed") {
        return Err(io::Error::other(format!(
            "isolated PAM test did not pass exactly one test ({status})\n{text}",
        )));
    }
    Ok(())
}
