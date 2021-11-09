/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Safe Rust interface to Android `libbinder`.
//!
//! This crate is primarily designed as an target for a Rust AIDL compiler
//! backend, and should generally not be used directly by users. It is built on
//! top of the binder NDK library to be usable by APEX modules, and therefore
//! only exposes functionality available in the NDK interface.
//!
//! # Example
//!
//! The following example illustrates how the AIDL backend will use this crate.
//!
//! ```
//! use binder::{
//!     declare_binder_interface, Binder, IBinder, Interface, Remotable, Parcel, SpIBinder,
//!     StatusCode, TransactionCode,
//! };
//!
//! // Generated by AIDL compiler
//! pub trait ITest: Interface {
//!     fn test(&self) -> binder::Result<String>;
//! }
//!
//! // Creates a new local (native) service object, BnTest, and a remote proxy
//! // object, BpTest, that are the typed interfaces for their respective ends
//! // of the binder transaction. Generated by AIDL compiler.
//! declare_binder_interface! {
//!     ITest["android.os.ITest"] {
//!         native: BnTest(on_transact),
//!         proxy: BpTest,
//!     }
//! }
//!
//! // Generated by AIDL compiler
//! fn on_transact(
//!     service: &dyn ITest,
//!     code: TransactionCode,
//!     _data: &BorrowedParcel,
//!     reply: &mut BorrowedParcel,
//! ) -> binder::Result<()> {
//!     match code {
//!         SpIBinder::FIRST_CALL_TRANSACTION => {
//!             reply.write(&service.test()?)?;
//!             Ok(())
//!         }
//!         _ => Err(StatusCode::UNKNOWN_TRANSACTION),
//!     }
//! }
//!
//! // Generated by AIDL compiler
//! impl ITest for Binder<BnTest> {
//!     fn test(&self) -> binder::Result<String> {
//!         self.0.test()
//!     }
//! }
//!
//! // Generated by AIDL compiler
//! impl ITest for BpTest {
//!     fn test(&self) -> binder::Result<String> {
//!        let reply = self
//!            .as_binder()
//!            .transact(SpIBinder::FIRST_CALL_TRANSACTION, 0, |_| Ok(()))?;
//!        reply.read()
//!     }
//! }
//!
//! // User implemented:
//!
//! // Local implementation of the ITest remotable interface.
//! struct TestService;
//!
//! impl Interface for TestService {}
//!
//! impl ITest for TestService {
//!     fn test(&self) -> binder::Result<String> {
//!        Ok("testing service".to_string())
//!     }
//! }
//! ```

#[macro_use]
mod proxy;

#[macro_use]
mod binder;
mod binder_async;
mod error;
mod native;
mod state;

use binder_ndk_sys as sys;

pub mod parcel;

pub use crate::binder::{
    BinderFeatures, FromIBinder, IBinder, IBinderInternal, Interface, InterfaceClass, Remotable,
    Stability, Strong, TransactionCode, TransactionFlags, Weak, FIRST_CALL_TRANSACTION,
    FLAG_CLEAR_BUF, FLAG_ONEWAY, FLAG_PRIVATE_LOCAL, LAST_CALL_TRANSACTION,
};
pub use crate::binder_async::{BoxFuture, BinderAsyncPool};
pub use error::{status_t, ExceptionCode, Result, Status, StatusCode};
pub use native::{add_service, force_lazy_services_persist, register_lazy_service, Binder};
pub use parcel::{BorrowedParcel, Parcel};
pub use proxy::{get_interface, get_service, wait_for_interface, wait_for_service};
pub use proxy::{AssociateClass, DeathRecipient, Proxy, SpIBinder, WpIBinder};
pub use state::{ProcessState, ThreadState};

/// Unstable, in-development API that only allowlisted clients are allowed to use.
pub mod unstable_api {
    pub use crate::binder::AsNative;
    pub use crate::proxy::unstable_api::new_spibinder;
    pub use crate::sys::AIBinder;
}

/// The public API usable outside AIDL-generated interface crates.
pub mod public_api {
    pub use super::parcel::{ParcelFileDescriptor, ParcelableHolder};
    pub use super::{
        add_service, force_lazy_services_persist, get_interface, register_lazy_service,
        wait_for_interface,
    };
    pub use super::{
        BinderAsyncPool, BinderFeatures, BoxFuture, DeathRecipient, ExceptionCode, IBinder,
        Interface, ProcessState, SpIBinder, Status, StatusCode, Strong, ThreadState, Weak,
        WpIBinder,
    };

    /// Binder result containing a [`Status`] on error.
    pub type Result<T> = std::result::Result<T, Status>;
}
