// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

#![doc = include_str!("../README.md")]

#[doc(hidden)]
pub mod cli;
pub mod config;
pub(crate) mod pesign;
mod service;

use std::path::PathBuf;

#[doc(hidden)]
pub use service::listen;

/// Unifying structure for the CLI options and configuration file.
#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct Context {
    pub(crate) runtime_directory: PathBuf,
    pub(crate) credentials_directory: PathBuf,
    pub(crate) config: config::Config,
}

impl Context {
    pub fn new(
        config: config::Config,
        runtime_directory: PathBuf,
        credentials_directory: PathBuf,
    ) -> anyhow::Result<Self> {
        // if multiple runtime directories were provided, we don't know which to use so panic for now.
        if runtime_directory
            .to_str()
            .ok_or(anyhow::anyhow!(
                "runtime_directory must be valid unicode characters"
            ))?
            .contains(':')
        {
            return Err(anyhow::anyhow!(
                "Multiple RuntimeDirectories are not supported"
            ));
        }

        Ok(Self {
            runtime_directory,
            credentials_directory,
            config,
        })
    }
}
