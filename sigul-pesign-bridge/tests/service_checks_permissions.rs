// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use std::process::{Command, Stdio};

use anyhow::Result;
use assert_cmd::cargo::CommandCargoExt;
use nix::sys::stat::Mode;

#[test]
fn stops_world_readable() -> Result<()> {
    let socket_dir = tempfile::tempdir()?;
    let socket_path = socket_dir.path().join("socket");
    let config_path = socket_dir.path().join("config.toml");
    let socket = socket_path.to_str().unwrap();
    let config = format!(
        "
        work_directory = /run/pesign/
        socket_path = {socket} 
        nss_database_passphrase_path = nss-database-passphrase
        request_timeout_secs = 900
    "
    );
    std::fs::write(config_path, config).unwrap();

    nix::sys::stat::umask(Mode::empty());
    let mut command = Command::cargo_bin("sigul-pesign-bridge")?;
    let output = command
        .env("SIGUL_PESIGN_BRIDGE_LOG", "trace")
        .arg("listen")
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .output()?;
    let logs = String::from_utf8_lossy(&output.stderr);
    println!("service_stderr: {logs}");
    assert!(!output.status.success());
    assert!(logs.contains("Other users have access to the socket, adjust the service umask!"));

    Ok(())
}
