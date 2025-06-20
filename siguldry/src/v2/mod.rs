// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

/*!
# Siguldry V2

This is a new implementation of the [Sigul][1] service with a new protocol version.

This new protocol, version 2, is heavily inspired by Sigul's 1.2 protocol. The key differences
are that unlike 1.2, all client-server communication happens in the nested TLS session, and as
such, it is no longer possible to mix traffic to the inner and outer TLS sessions: after
the protocol header is sent to the bridge, all traffic must be sent via the inner session.

Since the protocol has been changed, the command APIs have also been adjusted compared to Sigul's
1.2 implementation.

[1]: https://pagure.io/sigul
*/

pub mod bridge;
#[cfg(feature = "v2-client")]
pub mod client;
pub mod config;
pub mod error;
pub(crate) mod nestls;
pub(crate) mod protocol;
#[cfg(feature = "v2-server")]
pub mod server;
