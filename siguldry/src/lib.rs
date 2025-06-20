// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.
#![warn(missing_docs)]

/*!
# Siguldry

This crate provides a client for the [Sigul][1] service. In particular, it works with version
1.2.

It is still under active development and may, in the future, provide the primatives required to
build a Sigul bridge and Sigul server.


# Crate features

By default, only the library is provided. However, command-line interfaces are available behind
feature flags.

* **client-cli** -
  Build the Siguldry client CLI. This implements a sub-set of commands supported by the [Sigul][1] server.

[1]: https://pagure.io/sigul
*/

pub mod v1;
pub use v1::client;
pub use v1::error;
mod serdes;
pub mod v2;
