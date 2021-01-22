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

//! Included as a module in the binder crate internal tests for internal API
//! access.

use binder::declare_binder_interface;
use binder::{
    Binder, ExceptionCode, Interface, Parcel, Result, SpIBinder, Status,
    StatusCode, TransactionCode,
};
use binder::parcel::ParcelFileDescriptor;

use std::ffi::{c_void, CStr, CString};
use std::panic::{self, AssertUnwindSafe};
use std::sync::Once;

#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    improper_ctypes,
    missing_docs,
    clippy::all
)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

static SERVICE_ONCE: Once = Once::new();
static mut SERVICE: Option<SpIBinder> = None;

/// Start binder service and return a raw AIBinder pointer to it.
///
/// Safe to call multiple times, only creates the service once.
#[no_mangle]
pub extern "C" fn rust_service() -> *mut c_void {
    unsafe {
        SERVICE_ONCE.call_once(|| {
            SERVICE = Some(BnReadParcelTest::new_binder(()).as_binder());
        });
        SERVICE.as_ref().unwrap().as_raw().cast()
    }
}

/// Empty interface just to use the declare_binder_interface macro
pub trait ReadParcelTest: Interface {}

declare_binder_interface! {
    ReadParcelTest["read_parcel_test"] {
        native: BnReadParcelTest(on_transact),
        proxy: BpReadParcelTest,
    }
}

impl ReadParcelTest for Binder<BnReadParcelTest> {}

impl ReadParcelTest for BpReadParcelTest {}

impl ReadParcelTest for () {}

fn on_transact(
    _service: &dyn ReadParcelTest,
    code: TransactionCode,
    parcel: &Parcel,
    reply: &mut Parcel,
) -> Result<()> {
    panic::catch_unwind(AssertUnwindSafe(|| transact_inner(code, parcel, reply))).unwrap_or_else(
        |e| {
            eprintln!("Failure in Rust: {:?}", e.downcast_ref::<String>());
            Err(StatusCode::FAILED_TRANSACTION)
        },
    )
}

#[allow(clippy::float_cmp)]
fn transact_inner(code: TransactionCode, parcel: &Parcel, reply: &mut Parcel) -> Result<()> {
    match code {
        bindings::Transaction_TEST_BOOL => {
            assert_eq!(parcel.read::<bool>()?, true);
            assert_eq!(parcel.read::<bool>()?, false);
            assert_eq!(parcel.read::<Vec<bool>>()?, unsafe {
                bindings::TESTDATA_BOOL
            });
            assert_eq!(parcel.read::<Option<Vec<bool>>>()?, None);

            reply.write(&true)?;
            reply.write(&false)?;
            reply.write(&unsafe { bindings::TESTDATA_BOOL }[..])?;
            reply.write(&(None as Option<Vec<bool>>))?;
        }
        bindings::Transaction_TEST_BYTE => {
            assert_eq!(parcel.read::<i8>()?, 0);
            assert_eq!(parcel.read::<i8>()?, 1);
            assert_eq!(parcel.read::<i8>()?, i8::max_value());
            assert_eq!(parcel.read::<Vec<i8>>()?, unsafe { bindings::TESTDATA_I8 });
            assert_eq!(parcel.read::<Vec<u8>>()?, unsafe { bindings::TESTDATA_U8 });
            assert_eq!(parcel.read::<Option<Vec<i8>>>()?, None);

            reply.write(&0i8)?;
            reply.write(&1i8)?;
            reply.write(&i8::max_value())?;
            reply.write(&unsafe { bindings::TESTDATA_I8 }[..])?;
            reply.write(&unsafe { bindings::TESTDATA_U8 }[..])?;
            reply.write(&(None as Option<Vec<i8>>))?;
        }
        bindings::Transaction_TEST_U16 => {
            assert_eq!(parcel.read::<u16>()?, 0);
            assert_eq!(parcel.read::<u16>()?, 1);
            assert_eq!(parcel.read::<u16>()?, u16::max_value());
            assert_eq!(parcel.read::<Vec<u16>>()?, unsafe {
                bindings::TESTDATA_CHARS
            });
            assert_eq!(parcel.read::<Option<Vec<u16>>>()?, None);

            reply.write(&0u16)?;
            reply.write(&1u16)?;
            reply.write(&u16::max_value())?;
            reply.write(&unsafe { bindings::TESTDATA_CHARS }[..])?;
            reply.write(&(None as Option<Vec<u16>>))?;
        }
        bindings::Transaction_TEST_I32 => {
            assert_eq!(parcel.read::<i32>()?, 0);
            assert_eq!(parcel.read::<i32>()?, 1);
            assert_eq!(parcel.read::<i32>()?, i32::max_value());
            assert_eq!(parcel.read::<Vec<i32>>()?, unsafe {
                bindings::TESTDATA_I32
            });
            assert_eq!(parcel.read::<Option<Vec<i32>>>()?, None);

            reply.write(&0i32)?;
            reply.write(&1i32)?;
            reply.write(&i32::max_value())?;
            reply.write(&unsafe { bindings::TESTDATA_I32 }[..])?;
            reply.write(&(None as Option<Vec<i32>>))?;
        }
        bindings::Transaction_TEST_I64 => {
            assert_eq!(parcel.read::<i64>()?, 0);
            assert_eq!(parcel.read::<i64>()?, 1);
            assert_eq!(parcel.read::<i64>()?, i64::max_value());
            assert_eq!(parcel.read::<Vec<i64>>()?, unsafe {
                bindings::TESTDATA_I64
            });
            assert_eq!(parcel.read::<Option<Vec<i64>>>()?, None);

            reply.write(&0i64)?;
            reply.write(&1i64)?;
            reply.write(&i64::max_value())?;
            reply.write(&unsafe { bindings::TESTDATA_I64 }[..])?;
            reply.write(&(None as Option<Vec<i64>>))?;
        }
        bindings::Transaction_TEST_U64 => {
            assert_eq!(parcel.read::<u64>()?, 0);
            assert_eq!(parcel.read::<u64>()?, 1);
            assert_eq!(parcel.read::<u64>()?, u64::max_value());
            assert_eq!(parcel.read::<Vec<u64>>()?, unsafe {
                bindings::TESTDATA_U64
            });
            assert_eq!(parcel.read::<Option<Vec<u64>>>()?, None);

            reply.write(&0u64)?;
            reply.write(&1u64)?;
            reply.write(&u64::max_value())?;
            reply.write(&unsafe { bindings::TESTDATA_U64 }[..])?;
            reply.write(&(None as Option<Vec<u64>>))?;
        }
        bindings::Transaction_TEST_F32 => {
            assert_eq!(parcel.read::<f32>()?, 0f32);
            let floats = parcel.read::<Vec<f32>>()?;
            assert!(floats[0].is_nan());
            assert_eq!(floats[1..], unsafe { bindings::TESTDATA_FLOAT }[1..]);
            assert_eq!(parcel.read::<Option<Vec<f32>>>()?, None);

            reply.write(&0f32)?;
            reply.write(&unsafe { bindings::TESTDATA_FLOAT }[..])?;
            reply.write(&(None as Option<Vec<f32>>))?;
        }
        bindings::Transaction_TEST_F64 => {
            assert_eq!(parcel.read::<f64>()?, 0f64);
            let doubles = parcel.read::<Vec<f64>>()?;
            assert!(doubles[0].is_nan());
            assert_eq!(doubles[1..], unsafe { bindings::TESTDATA_DOUBLE }[1..]);
            assert_eq!(parcel.read::<Option<Vec<f64>>>()?, None);

            reply.write(&0f64)?;
            reply.write(&unsafe { bindings::TESTDATA_DOUBLE }[..])?;
            reply.write(&(None as Option<Vec<f64>>))?;
        }
        bindings::Transaction_TEST_STRING => {
            let s: Option<String> = parcel.read()?;
            assert_eq!(s.as_deref(), Some("testing"));
            let s: Option<String> = parcel.read()?;
            assert_eq!(s, None);
            let s: Option<Vec<Option<String>>> = parcel.read()?;
            for (s, expected) in s
                .unwrap()
                .iter()
                .zip(unsafe { bindings::TESTDATA_STRS }.iter())
            {
                let expected = unsafe {
                    expected
                        .as_ref()
                        .and_then(|e| CStr::from_ptr(e).to_str().ok())
                };
                assert_eq!(s.as_deref(), expected);
            }
            let s: Option<Vec<Option<String>>> = parcel.read()?;
            assert_eq!(s, None);

            let strings: Vec<Option<String>> = unsafe {
                bindings::TESTDATA_STRS
                    .iter()
                    .map(|s| {
                        s.as_ref().map(|s| {
                            CStr::from_ptr(s)
                                .to_str()
                                .expect("String was not UTF-8")
                                .to_owned()
                        })
                    })
                    .collect()
            };

            reply.write("testing")?;
            reply.write(&(None as Option<String>))?;
            reply.write(&strings)?;
            reply.write(&(None as Option<Vec<String>>))?;
        }
        bindings::Transaction_TEST_FILE_DESCRIPTOR => {
            let file1 = parcel.read::<ParcelFileDescriptor>()?;
            let file2 = parcel.read::<ParcelFileDescriptor>()?;
            let files = parcel.read::<Vec<Option<ParcelFileDescriptor>>>()?;

            reply.write(&file1)?;
            reply.write(&file2)?;
            reply.write(&files)?;
        }
        bindings::Transaction_TEST_IBINDER => {
            assert!(parcel.read::<Option<SpIBinder>>()?.is_some());
            assert!(parcel.read::<Option<SpIBinder>>()?.is_none());
            let ibinders = parcel.read::<Option<Vec<Option<SpIBinder>>>>()?.unwrap();
            assert_eq!(ibinders.len(), 2);
            assert!(ibinders[0].is_some());
            assert!(ibinders[1].is_none());
            assert!(parcel.read::<Option<Vec<Option<SpIBinder>>>>()?.is_none());

            let service = unsafe {
                SERVICE
                    .as_ref()
                    .expect("Global binder service not initialized")
                    .clone()
            };
            reply.write(&service)?;
            reply.write(&(None as Option<&SpIBinder>))?;
            reply.write(&[Some(&service), None][..])?;
            reply.write(&(None as Option<Vec<Option<&SpIBinder>>>))?;
        }
        bindings::Transaction_TEST_STATUS => {
            let status: Status = parcel.read()?;
            assert!(status.is_ok());
            let status: Status = parcel.read()?;
            assert_eq!(status.exception_code(), ExceptionCode::NULL_POINTER);
            assert_eq!(
                status.get_description(),
                "Status(-4, EX_NULL_POINTER): 'a status message'"
            );
            let status: Status = parcel.read()?;
            assert_eq!(status.service_specific_error(), 42);
            assert_eq!(
                status.get_description(),
                "Status(-8, EX_SERVICE_SPECIFIC): '42: a service-specific error'"
            );

            reply.write(&Status::ok())?;
            reply.write(&Status::new_exception(
                ExceptionCode::NULL_POINTER,
                Some(&CString::new("a status message").unwrap()),
            ))?;
            reply.write(&Status::new_service_specific_error(
                42,
                Some(&CString::new("a service-specific error").unwrap()),
            ))?;
        }
        bindings::Transaction_TEST_FAIL => {
            panic!("Testing expected failure");
        }
        _ => return Err(StatusCode::UNKNOWN_TRANSACTION),
    }

    assert_eq!(parcel.read::<i32>(), Err(StatusCode::NOT_ENOUGH_DATA));
    Ok(())
}
