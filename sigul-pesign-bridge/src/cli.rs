// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use std::path::PathBuf;

use clap::Parser;

use crate::config::{self, Config};

/// An alternative to the pesign daemon interface.
///
/// The Unix socket this service offers can be used by pesign-client. Rather
/// than signing the PE file, however, this application will act as a sigul
/// client and forward it to a sigul signing server.
///
/// Log configuration is provided using the "SIGUL_PESIGN_BRIDGE_LOG"
/// environment variable with one or more comma-separated directives. In short,
/// filters can be plain verbosity levels ("trace", "debug", "info", "warn",
/// "error"), or more complex filtering at the model, span, or event level.
#[derive(Parser, Debug)]
#[command(version)]
pub struct Cli {
    /// Path to the configuration file.
    ///
    /// If no path is provided, the defaults are used. To view the service
    /// defaults, run the `config` subcommand.
    #[arg(long, short, env = "SIGUL_PESIGN_BRIDGE_CONFIG", value_parser = config::load)]
    pub config: Option<Config>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    /// Run the service.
    ///
    /// The service provides a Unix socket at, by default, `/run/pesign/socket`.
    /// `pesign-client` can be used to connect to this socket and request
    /// signatures for PE applications. Unlike `pesign`, this implementation
    /// forwards the request to a Sigul signing server.
    Listen {
        /// The service's runtime directory.
        ///
        /// This is where the service socket is created, along with any temporary
        /// files. The socket name will be `socket` under this directory.
        ///
        /// Anyone with access to the socket can get a PE application signed, so
        /// care should be taken to ensure this directory is not world-readable.
        /// This directory should be read/writeable only to the service owner/group.
        /// Temporary files created within this directory are readable only to the
        /// owner, so users in the group can only acceess the socket.
        ///
        /// When run under systemd, providing a `RuntimeDirectory=` directive will
        /// set the environment variable automatically for you.
        #[arg(long, short, env = "RUNTIME_DIRECTORY")]
        runtime_directory: PathBuf,
    },
    /// Print the current service configuration to standard output.
    ///
    /// If no config file is provided, the defaults are printed. For complete
    /// details on each configuration option, refer to the the documentation.
    Config,
}
