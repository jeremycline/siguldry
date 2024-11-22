// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.
//
// Tests the integration with pesign-client.
//
// These tests require that the `pesign-client` binary be in your PATH.
// Additionally, since pesign-client doesn't offer a way to configure
// the socket it connects to, the user running the test must be able to
// read/write to `/run/pesign/socket`.

use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Output, Stdio},
    sync::{Mutex, Once},
    time::Duration,
};

use anyhow::{anyhow, Result};
use assert_cmd::cargo::CommandCargoExt;
use nix::sys::{
    signal::{self, Signal},
    stat::Mode,
};
use tempfile::{tempdir, NamedTempFile};

static UMASK: Once = Once::new();

// Since pesign-client can't have its socket path configured, we need to limit
// the tests to ensure one server is running at a time :(
static SOCKET_PERMIT: Mutex<()> = Mutex::new(());

fn run_command(mut client_command: Command) -> Result<(Output, Output)> {
    UMASK.call_once(|| {
        let mut umask = Mode::empty();
        umask.insert(Mode::S_IRWXO);
        nix::sys::stat::umask(umask);
    });
    let _socket_permit = SOCKET_PERMIT.lock().unwrap();

    let socket_path = "/run/pesign/socket";
    if let Ok(_metadata) = std::fs::metadata(socket_path) {
        return Err(anyhow!(
            "{socket_path} exists; unable to start test instance"
        ));
    };
    let working_dir = tempdir()?;
    let mut server_command = Command::cargo_bin("sigul-pesign-bridge")?;
    server_command
        .env("RUNTIME_DIRECTORY", working_dir.path())
        .env("SIGUL_PESIGN_BRIDGE_LOG", "trace")
        .arg("listen")
        .stderr(Stdio::piped())
        .stdout(Stdio::piped());
    let service = server_command.spawn()?;

    let mut tries = 0;
    while let Err(error) = std::fs::metadata(socket_path) {
        std::thread::sleep(Duration::from_millis(5));
        tries += 1;
        if tries > 100 {
            return Err(anyhow!("Failed to start service: {error:?}"));
        }
    }

    let client_output = client_command.output()?;
    println!(
        "client_stdout: {}",
        String::from_utf8_lossy(&client_output.stdout)
    );
    println!(
        "client_stderr: {}",
        String::from_utf8_lossy(&client_output.stderr)
    );

    signal::kill(
        nix::unistd::Pid::from_raw(service.id().try_into()?),
        Signal::SIGTERM,
    )?;
    let service_output = service.wait_with_output()?;
    println!(
        "service_stderr: {}",
        String::from_utf8_lossy(&service_output.stderr)
    );

    Ok((client_output, service_output))
}

// Test that the daemon implements the "is-unlocked" command.
#[test]
fn is_unlocked() -> Result<()> {
    let mut client_command = Command::new("pesign-client");
    client_command
        .arg("--is-unlocked")
        .arg("--token=Test Cert DB");
    let (client_output, service_output) = run_command(client_command)?;

    assert!(client_output.status.success());
    assert_eq!(
        "token \"Test Cert DB\" is unlocked\n",
        String::from_utf8_lossy(&client_output.stdout)
    );
    assert!(service_output.status.success());

    Ok(())
}

#[test]
fn sign_attached() -> Result<()> {
    let output_dir = tempfile::tempdir()?;
    let out_file = output_dir.path().join("sample-uefi.signed.efi");
    let mut in_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    in_file.push("../target/x86_64-unknown-uefi/debug/sample-uefi.efi");

    let mut client_command = Command::new("pesign-client");
    client_command
        .arg("--sign")
        .arg("--token=signing-key")
        .arg("--certificate=codesigning")
        .arg(format!("--infile={}", in_file.as_path().display()))
        .arg(format!("--outfile={}", &out_file.as_path().display()));
    let (client_output, service_output) = run_command(client_command)?;

    assert!(client_output.status.success());
    assert!(service_output.status.success());

    let input_signature_list = Command::new("sbverify")
        .arg("--list")
        .arg(in_file.as_path())
        .output()?;
    println!("{}", String::from_utf8_lossy(&input_signature_list.stderr));
    println!(
        "stdout: {}",
        String::from_utf8_lossy(&input_signature_list.stdout)
    );
    let output_signature_list = Command::new("sbverify")
        .arg("--list")
        .arg(&out_file)
        .output()?;
    println!("{}", String::from_utf8_lossy(&output_signature_list.stderr));
    println!(
        "stdout: {}",
        String::from_utf8_lossy(&output_signature_list.stdout)
    );

    let mut signing_cert = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    signing_cert.push("../keys/signing-cert.pem");
    let output_signed = Command::new("sbverify")
        .arg("--cert")
        .arg(&signing_cert)
        .arg(&out_file)
        .output()?;
    assert!(output_signed.status.success());
    let input_signed = Command::new("sbverify")
        .arg("--cert")
        .arg(signing_cert)
        .arg(in_file)
        .output()?;
    assert!(!input_signed.status.success());

    Ok(())
}

// Test the daemon reponds gracefully to the unlock command, which is not supported.
#[test]
fn unlock() -> Result<()> {
    let mut pinfile = NamedTempFile::new()?;
    pinfile.write_all(b"secret_password\n")?;

    let mut client_command = Command::new("pesign-client");
    client_command
        .arg("--unlock")
        .arg(format!("--pinfile={}", pinfile.path().display()))
        .arg("--token=Test Cert DB");
    let (client_output, service_output) = run_command(client_command)?;

    assert!(!client_output.status.success());
    assert_eq!(
        "pesign-client: command \"unlock-token\" not known by server\n",
        String::from_utf8_lossy(&client_output.stderr)
    );
    assert!(service_output.status.success());
    let service_logs = String::from_utf8_lossy(&service_output.stderr);
    assert!(service_logs.contains(
        "Client queried for the server version of command UnlockToken, which is not supported"
    ));

    Ok(())
}

// Test the daemon reponds gracefully to the kill command, which is not supported.
#[test]
fn kill() -> Result<()> {
    let mut client_command = Command::new("pesign-client");
    client_command.arg("--kill");
    let (client_output, service_output) = run_command(client_command)?;

    assert!(!client_output.status.success());
    assert_eq!(
        "pesign-client: command \"kill-daemon\" not known by server\n",
        String::from_utf8_lossy(&client_output.stderr)
    );
    assert!(service_output.status.success());
    let service_logs = String::from_utf8_lossy(&service_output.stderr);
    assert!(service_logs
        .contains("Client queried for the server version of command Kill, which is not supported"));

    Ok(())
}
