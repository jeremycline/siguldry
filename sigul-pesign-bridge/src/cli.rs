// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use clap::Parser;

use crate::config::{self, Config};

/// An alternative to the pesign daemon interface.
///
/// Rather than signing the PE file, however, this application will act as a sigul client and
/// forward it to a sigul signing server.
///
/// Log configuration is provided using the "SIGUL_PESIGN_BRIDGE_LOG"
/// environment variable with one or more comma-separated directives. In short,
/// filters can be plain verbosity levels ("trace", "debug", "info", "warn",
/// "error"), or more complex filtering at the span or event level.
///
/// The complete format is documented at
/// https://docs.rs/tracing-subscriber/0.3.19/tracing_subscriber/filter/struct.EnvFilter.html#directives.
///
/// The Unix socket this service offers can be used by pesign-client.
#[derive(Parser, Debug)]
#[command(version)]
pub(crate) struct Cli {
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
pub(crate) enum Command {
    /// Run the service.
    Listen,
    /// Print the current service configuration to standard output.
    ///
    /// If no config file is provided, the defaults are printed. For complete details on each
    /// configuration option, refer to the the documentation.
    Config,
}
