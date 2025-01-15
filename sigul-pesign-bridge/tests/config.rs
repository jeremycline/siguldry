// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use std::process::{Command, Stdio};

use anyhow::Result;
use assert_cmd::cargo::CommandCargoExt;

#[test]
fn config_with_default_works() -> Result<()> {
    let mut command = Command::cargo_bin("sigul-pesign-bridge")?;
    let output = command
        .arg("config")
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .output()?;
    let logs = String::from_utf8_lossy(&output.stdout);
    println!("cli_stdout: {logs}");
    assert!(output.status.success());
    assert!(logs.contains(
        "Current configuration:

sigul_client_config = \"sigul-client-config\"
request_timeout_secs = 900

[[keys]]
key_name = \"signing-key\"
certificate_name = \"codesigning\"
passphrase_path = \"sigul-signing-key-passphrase\"
"
    ));

    Ok(())
}
