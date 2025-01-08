// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use std::{env, path::PathBuf};

use anyhow::anyhow;
use clap::CommandFactory;

#[derive(Debug)]
enum Task {
    Manual,
}

impl TryFrom<&str> for Task {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "manual" => Ok(Task::Manual),
            _ => Err(anyhow!("Unknown task")),
        }
    }
}

fn main() -> anyhow::Result<()> {
    let task: Task = env::args()
        .nth(1)
        .ok_or(anyhow!("Must provide a task"))?
        .as_str()
        .try_into()?;
    match task {
        Task::Manual => generate_manual(),
    }
}

fn generate_manual() -> anyhow::Result<()> {
    let outdir = PathBuf::from(env::var_os("OUT_DIR").ok_or(anyhow!("Must set OUT_DIR"))?);
    let command = sigul_pesign_bridge::cli::Cli::command();
    let manual = clap_mangen::Man::new(command);
    manual.generate_to(outdir)?;

    Ok(())
}
