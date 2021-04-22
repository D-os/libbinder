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

//! Rust Binder NDK interop tests

use ::IBinderRustNdkInteropTest::aidl::IBinderRustNdkInteropTest::{
    BnBinderRustNdkInteropTest, IBinderRustNdkInteropTest,
};
use ::IBinderRustNdkInteropTest::aidl::IBinderRustNdkInteropTestOther::IBinderRustNdkInteropTestOther;
use ::IBinderRustNdkInteropTest::binder::{self, BinderFeatures, Interface, StatusCode};
use std::ffi::CStr;
use std::os::raw::{c_char, c_int};

/// Look up the provided AIDL service and call its echo method.
///
/// # Safety
///
/// service_name must be a valid, non-null C-style string (null-terminated).
#[no_mangle]
pub unsafe extern "C" fn rust_call_ndk(service_name: *const c_char) -> c_int {
    let service_name = CStr::from_ptr(service_name).to_str().unwrap();

    // The Rust class descriptor pointer will not match the NDK one, but the
    // descriptor strings match so this needs to still associate.
    let service: binder::Strong<dyn IBinderRustNdkInteropTest> =
        match binder::get_interface(service_name) {
            Err(e) => {
                eprintln!("Could not find Ndk service {}: {:?}", service_name, e);
                return StatusCode::NAME_NOT_FOUND as c_int;
            }
            Ok(service) => service,
        };

    match service.echo("testing") {
        Ok(s) => {
            if s != "testing" {
                return StatusCode::BAD_VALUE as c_int;
            }
        }
        Err(e) => return e.into(),
    }

    // Try using the binder service through the wrong interface type
    let wrong_service: Result<binder::Strong<dyn IBinderRustNdkInteropTestOther>, StatusCode> =
        binder::get_interface(service_name);
    match wrong_service {
        Err(e) if e == StatusCode::BAD_TYPE => {}
        Err(e) => {
            eprintln!("Trying to use a service via the wrong interface errored with unexpected error {:?}", e);
            return e as c_int;
        }
        Ok(_) => {
            eprintln!("We should not be allowed to use a service via the wrong interface");
            return StatusCode::BAD_TYPE as c_int;
        }
    }

    StatusCode::OK as c_int
}

struct Service;

impl Interface for Service {}

impl IBinderRustNdkInteropTest for Service {
    fn echo(&self, s: &str) -> binder::Result<String> {
        Ok(s.to_string())
    }
}

/// Start the interop Echo test service with the given service name.
///
/// # Safety
///
/// service_name must be a valid, non-null C-style string (null-terminated).
#[no_mangle]
pub unsafe extern "C" fn rust_start_service(service_name: *const c_char) -> c_int {
    let service_name = CStr::from_ptr(service_name).to_str().unwrap();
    let service = BnBinderRustNdkInteropTest::new_binder(Service, BinderFeatures::default());
    match binder::add_service(&service_name, service.as_binder()) {
        Ok(_) => StatusCode::OK as c_int,
        Err(e) => e as c_int,
    }
}
