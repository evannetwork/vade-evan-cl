/*
  Copyright (c) 2018-present evan GmbH.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

//! This crate allows you to use to work with zero knowledge proof VCs on Trust and Trace, which runs on evan.network.
//! For this purpose a [`VadePlugin`] implementation  exported: [`VadeEvanCl`].
//!
//! ## VadeEvanCl
//!
//! Responsible for working with zero knowledge proof VCs on Trust and Trace.
//!
//! Implements the following [`VadePlugin`] functions:
//!
//! - [`vc_zkp_create_credential_schema`]
//! - [`vc_zkp_create_credential_definition`]
//! - [`vc_zkp_create_credential_proposal`]
//! - [`vc_zkp_create_credential_offer`]
//! - [`vc_zkp_request_credential`]
//! - [`vc_zkp_create_revocation_registry_definition`]
//! - [`vc_zkp_update_revocation_registry`]
//! - [`vc_zkp_issue_credential`]
//! - [`vc_zkp_revoke_credential`]
//! - [`vc_zkp_request_proof`]
//! - [`vc_zkp_present_proof`]
//! - [`vc_zkp_verify_proof`]
//! - [`run_custom_function`]
//!
//! ## Compiling vade-evan-cl
//!
//! ### "Regular" build
//!
//! No surprise here:
//!
//! ```sh
//! cargo build --release
//! ```
//!
//! ### Default Features
//!
//! By default features `did`, `native`, and `vc-zkp` are used. So everything included and available for usage in other Rust libraries.
//!
//! Features can be omitted. This mostly concerns, the `vc-zkp` feature, as it can be dropped without affecting the `did` functionality. `did` can be omitted as well but will most probably limit usability `vc-zkp` functionalities as this relies on `did` logic for some parts of its logic.
//!
//! In short: Use either `did` and `vc-zkp` together (default) or just `did`.
//!
//! ### Command Line Interface
//!
//! To enable the cli just add the feature `cli` to the feature set:
//!
//! ```sh
//! cargo build --release --features cli
//! ```
//!
//! You can now use the `vade-evan-cl` cli. Get started by having a look at the help shown after calling it with:
//!
//! ```sh
//! ./target/release/vade_evan_cli_cli
//! ```
//!
//! ### WASM
//!
//! To compile `vade-evan-cl` for wasm, use wasm pack.
//!
//! You can specify to use only `did` feature or to use `did` and `vc-zkp`. The following examples will use both features.
//!
//! Also you have to specify whether to build a browser or a nodejs environment.
//!
//! nodejs:
//!
//! ```sh
//! wasm-pack build --release --target nodejs -- --no-default-features --features did,vc-zkp,wasm
//! ```
//!
//! browser:
//!
//! ```sh
//! wasm-pack build --release --target web -- --no-default-features --features did,vc-zkp,wasm
//! ```
//!
//! ### Features for building
//!
//! | feature  | default | contents |
//! | -------- |:-------:| -------- |
//! | portable |     x   | build with optimizations to run natively, not compatible with `wasm` feature |
//! | wasm     |         | build with optimizations to run as web assembly, not compatible with `native` |
//!
//! [`VadeEvanCl`]: https://docs.rs/vade_evan_cli/*/vade_evan_cli/resolver/struct.VadeEvanCl.html
//! [`Vade`]: https://docs.rs/vade_evan_cli/*/vade/struct.Vade.html
//! [`VadePlugin`]: https://docs.rs/vade_evan_cli/*/vade/trait.VadePlugin.html
//! [`VadeEvanCl`]: https://docs.rs/vade_evan_cli/*/vade_evan_cli/struct.VadeEvanCl.html
//! [`vc_zkp_create_credential_definition`]: https://docs.rs/vade_evan_cli/*/vade_evan_cli/struct.VadeEvanCl.html#method.vc_zkp_create_credential_definition
//! [`vc_zkp_create_credential_offer`]: https://docs.rs/vade_evan_cli/*/vade_evan_cli/struct.VadeEvanCl.html#method.vc_zkp_create_credential_offer
//! [`vc_zkp_create_credential_proposal`]: https://docs.rs/vade_evan_cli/*/vade_evan_cli/struct.VadeEvanCl.html#method.vc_zkp_create_credential_proposal
//! [`vc_zkp_create_credential_schema`]: https://docs.rs/vade_evan_cli/*/vade_evan_cli/struct.VadeEvanCl.html#method.vc_zkp_create_credential_schema
//! [`vc_zkp_create_revocation_registry_definition`]: https://docs.rs/vade_evan_cli/*/vade_evan_cli/struct.VadeEvanCl.html#method.vc_zkp_create_revocation_registry_definition
//! [`vc_zkp_issue_credential`]: https://docs.rs/vade_evan_cli/*/vade_evan_cli/struct.VadeEvanCl.html#method.vc_zkp_issue_credential
//! [`vc_zkp_present_proof`]: https://docs.rs/vade_evan_cli/*/vade_evan_cli/struct.VadeEvanCl.html#method.vc_zkp_present_proof
//! [`vc_zkp_request_credential`]: https://docs.rs/vade_evan_cli/*/vade_evan_cli/struct.VadeEvanCl.html#method.vc_zkp_request_credential
//! [`vc_zkp_request_proof`]: https://docs.rs/vade_evan_cli/*/vade_evan_cli/struct.VadeEvanCl.html#method.vc_zkp_request_proof
//! [`vc_zkp_revoke_credential`]: https://docs.rs/vade_evan_cli/*/vade_evan_cli/struct.VadeEvanCl.html#method.vc_zkp_revoke_credential
//! [`vc_zkp_update_revocation_registry`]: https://docs.rs/vade_evan_cli/*/vade_evan_cli/struct.VadeEvanCl.html#method.vc_zkp_update_revocation_registry
//! [`vc_zkp_verify_proof`]: https://docs.rs/vade_evan_cli/*/vade_evan_cli/struct.VadeEvanCl.html#method.vc_zkp_verify_proof
//! [`run_custom_function`]: https://docs.rs/vade_evan_cli/*/vade_evan_cli/struct.VadeEvanCl.html#method.run_custom_function

#[macro_use]
pub extern crate log;
pub extern crate vade_evan_substrate;

// --------- mod
// shared
pub mod utils;

pub mod application;
pub mod crypto;
mod vade_evan_cl;

// wasm only
#[cfg(target_arch = "wasm32")]
pub mod wasm_lib;

// --------- use
pub use self::vade_evan_cl::*;
