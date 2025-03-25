// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use std::{env, path::PathBuf};

use anyhow::anyhow;
use clap::CommandFactory;

const TASKS: [&str; 2] = ["manual", "extract-keys"];

fn main() -> anyhow::Result<()> {
    match env::args()
        .nth(1)
        .ok_or(anyhow!("Must provide a task"))?
        .as_str()
    {
        "manual" => generate_manual(),
        "extract-keys" => extract_keys(),
        _ => Err(anyhow!("Unknown task, use one of {:?}", TASKS)),
    }
}

fn generate_manual() -> anyhow::Result<()> {
    let mut root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.push("../");

    let outdir = root.join("sigul-pesign-bridge/docs/");
    let command = sigul_pesign_bridge::cli::Cli::command();
    let manual = clap_mangen::Man::new(command);
    manual.generate_to(outdir)?;

    Ok(())
}

fn extract_keys() -> anyhow::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let outdir = root.join("../devel/creds");
    let image = env::args()
        .nth(2)
        .unwrap_or_else(|| "quay.io/jeremycline/sigul-pesign-bridge-ci:latest".to_string());
    println!("Extracting keys from {}", &image);

    let mut command = std::process::Command::new("podman");
    command.args(["create", "--name=sigul-ci-key-extract", &image]);
    if !command.output()?.status.success() {
        anyhow::bail!("Failed to create container (have you pulled it?)");
    }

    // Drop the existing credentials or the new ones end up in devel/creds/creds
    let _ = std::fs::remove_dir_all(&outdir);
    let mut command = std::process::Command::new("podman");
    command.args(["cp", "sigul-ci-key-extract:/srv/siguldry/creds"]);
    command.arg(outdir);
    let output = command.output()?;
    if !output.status.success() {
        anyhow::bail!(
            "Failed to extract keys: {:?}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let mut command = std::process::Command::new("podman");
    command.args(["rm", "sigul-ci-key-extract"]);
    if !command.output()?.status.success() {
        anyhow::bail!("Failed to remove container 'sigul-ci-key-extract'");
    }

    Ok(())
}
