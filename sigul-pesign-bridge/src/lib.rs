// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

#![doc = include_str!("../README.md")]

#[doc(hidden)]
pub mod cli;
pub mod config;
mod service;

#[doc(hidden)]
pub use service::listen;
