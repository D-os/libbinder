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

use crate::binder::{AsNative, FromIBinder};
use crate::error::{status_result, Result, Status, StatusCode};
use crate::parcel::Parcel;
use crate::proxy::SpIBinder;
use crate::sys;

use std::convert::TryInto;
use std::ffi::{c_void, CStr, CString};
use std::ptr;

/// A struct whose instances can be written to a [`Parcel`].
// Might be able to hook this up as a serde backend in the future?
pub trait Serialize {
    /// Serialize this instance into the given [`Parcel`].
    fn serialize(&self, parcel: &mut Parcel) -> Result<()>;
}

/// A struct whose instances can be restored from a [`Parcel`].
// Might be able to hook this up as a serde backend in the future?
pub trait Deserialize: Sized {
    /// Deserialize an instance from the given [`Parcel`].
    fn deserialize(parcel: &Parcel) -> Result<Self>;
}

/// Helper trait for types that can be serialized as arrays.
/// Defaults to calling Serialize::serialize() manually for every element,
/// but can be overridden for custom implementations like `writeByteArray`.
// Until specialization is stabilized in Rust, we need this to be a separate
// trait because it's the only way to have a default implementation for a method.
// We want the default implementation for most types, but an override for
// a few special ones like `readByteArray` for `u8`.
pub trait SerializeArray: Serialize + Sized {
    /// Serialize an array of this type into the given [`Parcel`].
    fn serialize_array(slice: &[Self], parcel: &mut Parcel) -> Result<()> {
        parcel.write_slice_size(Some(slice))?;

        for item in slice {
            parcel.write(item)?;
        }

        Ok(())
    }
}

/// Helper trait for types that can be deserialized as arrays.
/// Defaults to calling Deserialize::deserialize() manually for every element,
/// but can be overridden for custom implementations like `readByteArray`.
pub trait DeserializeArray: Deserialize {
    /// Deserialize an array of type from the given [`Parcel`].
    fn deserialize_array(parcel: &Parcel) -> Result<Option<Vec<Self>>> {
        let len: i32 = parcel.read()?;
        if len < 0 {
            return Ok(None);
        }

        // TODO: Assumes that usize is at least 32 bits
        let mut vec = Vec::with_capacity(len as usize);

        for _ in 0..len {
            vec.push(parcel.read()?);
        }

        Ok(Some(vec))
    }
}

/// Helper trait for types that can be nullable when serialized.
// We really need this trait instead of implementing `Serialize for Option<T>`
// because of the Rust orphan rule which prevents us from doing
// `impl Serialize for Option<&dyn IFoo>` for AIDL interfaces.
// Instead we emit `impl SerializeOption for dyn IFoo` which is allowed.
// We also use it to provide a default implementation for AIDL-generated
// parcelables.
pub trait SerializeOption: Serialize {
    /// Serialize an Option of this type into the given [`Parcel`].
    fn serialize_option(this: Option<&Self>, parcel: &mut Parcel) -> Result<()> {
        if let Some(inner) = this {
            parcel.write(&1i32)?;
            parcel.write(inner)
        } else {
            parcel.write(&0i32)
        }
    }
}

/// Helper trait for types that can be nullable when deserialized.
pub trait DeserializeOption: Deserialize {
    /// Deserialize an Option of this type from the given [`Parcel`].
    fn deserialize_option(parcel: &Parcel) -> Result<Option<Self>> {
        let null: i32 = parcel.read()?;
        if null == 0 {
            Ok(None)
        } else {
            parcel.read().map(Some)
        }
    }
}

/// Callback to allocate a vector for parcel array read functions.
///
/// # Safety
///
/// The opaque data pointer passed to the array read function must be a mutable
/// pointer to an `Option<Vec<T>>`. `buffer` will be assigned a mutable pointer
/// to the allocated vector data if this function returns true.
unsafe extern "C" fn allocate_vec<T: Clone + Default>(
    data: *mut c_void,
    len: i32,
    buffer: *mut *mut T,
) -> bool {
    let vec = &mut *(data as *mut Option<Vec<T>>);
    if len < 0 {
        *vec = None;
        return true;
    }
    let mut new_vec: Vec<T> = Vec::with_capacity(len as usize);
    new_vec.resize_with(len as usize, Default::default);
    *buffer = new_vec.as_mut_ptr();
    *vec = Some(new_vec);
    true
}

macro_rules! parcelable_primitives {
    {
        $(
            impl $trait:ident for $ty:ty = $fn:path;
        )*
    } => {
        $(impl_parcelable!{$trait, $ty, $fn})*
    };
}

macro_rules! impl_parcelable {
    {Serialize, $ty:ty, $write_fn:path} => {
        impl Serialize for $ty {
            fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
                unsafe {
                    // Safety: `Parcel` always contains a valid pointer to an
                    // `AParcel`, and any `$ty` literal value is safe to pass to
                    // `$write_fn`.
                    status_result($write_fn(parcel.as_native_mut(), *self))
                }
            }
        }
    };

    {Deserialize, $ty:ty, $read_fn:path} => {
        impl Deserialize for $ty {
            fn deserialize(parcel: &Parcel) -> Result<Self> {
                let mut val = Self::default();
                unsafe {
                    // Safety: `Parcel` always contains a valid pointer to an
                    // `AParcel`. We pass a valid, mutable pointer to `val`, a
                    // literal of type `$ty`, and `$read_fn` will write the
                    // value read into `val` if successful
                    status_result($read_fn(parcel.as_native(), &mut val))?
                };
                Ok(val)
            }
        }
    };

    {SerializeArray, $ty:ty, $write_array_fn:path} => {
        impl SerializeArray for $ty {
            fn serialize_array(slice: &[Self], parcel: &mut Parcel) -> Result<()> {
                let status = unsafe {
                    // Safety: `Parcel` always contains a valid pointer to an
                    // `AParcel`. If the slice is > 0 length, `slice.as_ptr()`
                    // will be a valid pointer to an array of elements of type
                    // `$ty`. If the slice length is 0, `slice.as_ptr()` may be
                    // dangling, but this is safe since the pointer is not
                    // dereferenced if the length parameter is 0.
                    $write_array_fn(
                        parcel.as_native_mut(),
                        slice.as_ptr(),
                        slice
                            .len()
                            .try_into()
                            .or(Err(StatusCode::BAD_VALUE))?,
                    )
                };
                status_result(status)
            }
        }
    };

    {DeserializeArray, $ty:ty, $read_array_fn:path} => {
        impl DeserializeArray for $ty {
            fn deserialize_array(parcel: &Parcel) -> Result<Option<Vec<Self>>> {
                let mut vec: Option<Vec<Self>> = None;
                let status = unsafe {
                    // Safety: `Parcel` always contains a valid pointer to an
                    // `AParcel`. `allocate_vec<T>` expects the opaque pointer to
                    // be of type `*mut Option<Vec<T>>`, so `&mut vec` is
                    // correct for it.
                    $read_array_fn(
                        parcel.as_native(),
                        &mut vec as *mut _ as *mut c_void,
                        Some(allocate_vec),
                    )
                };
                status_result(status)?;
                Ok(vec)
            }
        }
    };
}

parcelable_primitives! {
    impl Serialize for bool = sys::AParcel_writeBool;
    impl Deserialize for bool = sys::AParcel_readBool;

    // This is only safe because `Option<Vec<u8>>` is interchangeable with
    // `Option<Vec<i8>>` (what the allocator function actually allocates.
    impl DeserializeArray for u8 = sys::AParcel_readByteArray;

    impl Serialize for i8 = sys::AParcel_writeByte;
    impl Deserialize for i8 = sys::AParcel_readByte;
    impl SerializeArray for i8 = sys::AParcel_writeByteArray;
    impl DeserializeArray for i8 = sys::AParcel_readByteArray;

    impl Serialize for u16 = sys::AParcel_writeChar;
    impl Deserialize for u16 = sys::AParcel_readChar;
    impl SerializeArray for u16 = sys::AParcel_writeCharArray;
    impl DeserializeArray for u16 = sys::AParcel_readCharArray;

    // This is only safe because `Option<Vec<i16>>` is interchangeable with
    // `Option<Vec<u16>>` (what the allocator function actually allocates.
    impl DeserializeArray for i16 = sys::AParcel_readCharArray;

    impl Serialize for u32 = sys::AParcel_writeUint32;
    impl Deserialize for u32 = sys::AParcel_readUint32;
    impl SerializeArray for u32 = sys::AParcel_writeUint32Array;
    impl DeserializeArray for u32 = sys::AParcel_readUint32Array;

    impl Serialize for i32 = sys::AParcel_writeInt32;
    impl Deserialize for i32 = sys::AParcel_readInt32;
    impl SerializeArray for i32 = sys::AParcel_writeInt32Array;
    impl DeserializeArray for i32 = sys::AParcel_readInt32Array;

    impl Serialize for u64 = sys::AParcel_writeUint64;
    impl Deserialize for u64 = sys::AParcel_readUint64;
    impl SerializeArray for u64 = sys::AParcel_writeUint64Array;
    impl DeserializeArray for u64 = sys::AParcel_readUint64Array;

    impl Serialize for i64 = sys::AParcel_writeInt64;
    impl Deserialize for i64 = sys::AParcel_readInt64;
    impl SerializeArray for i64 = sys::AParcel_writeInt64Array;
    impl DeserializeArray for i64 = sys::AParcel_readInt64Array;

    impl Serialize for f32 = sys::AParcel_writeFloat;
    impl Deserialize for f32 = sys::AParcel_readFloat;
    impl SerializeArray for f32 = sys::AParcel_writeFloatArray;
    impl DeserializeArray for f32 = sys::AParcel_readFloatArray;

    impl Serialize for f64 = sys::AParcel_writeDouble;
    impl Deserialize for f64 = sys::AParcel_readDouble;
    impl SerializeArray for f64 = sys::AParcel_writeDoubleArray;
    impl DeserializeArray for f64 = sys::AParcel_readDoubleArray;
}

impl SerializeArray for bool {}
impl DeserializeArray for bool {}

impl Serialize for u8 {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        (*self as i8).serialize(parcel)
    }
}

impl Deserialize for u8 {
    fn deserialize(parcel: &Parcel) -> Result<Self> {
        i8::deserialize(parcel).map(|v| v as u8)
    }
}

impl SerializeArray for u8 {
    fn serialize_array(slice: &[Self], parcel: &mut Parcel) -> Result<()> {
        let status = unsafe {
            // Safety: `Parcel` always contains a valid pointer to an
            // `AParcel`. If the slice is > 0 length, `slice.as_ptr()` will be a
            // valid pointer to an array of elements of type `$ty`. If the slice
            // length is 0, `slice.as_ptr()` may be dangling, but this is safe
            // since the pointer is not dereferenced if the length parameter is
            // 0.
            sys::AParcel_writeByteArray(
                parcel.as_native_mut(),
                slice.as_ptr() as *const i8,
                slice.len().try_into().or(Err(StatusCode::BAD_VALUE))?,
            )
        };
        status_result(status)
    }
}

impl Serialize for i16 {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        (*self as u16).serialize(parcel)
    }
}

impl Deserialize for i16 {
    fn deserialize(parcel: &Parcel) -> Result<Self> {
        u16::deserialize(parcel).map(|v| v as i16)
    }
}

impl SerializeArray for i16 {
    fn serialize_array(slice: &[Self], parcel: &mut Parcel) -> Result<()> {
        let status = unsafe {
            // Safety: `Parcel` always contains a valid pointer to an
            // `AParcel`. If the slice is > 0 length, `slice.as_ptr()` will be a
            // valid pointer to an array of elements of type `$ty`. If the slice
            // length is 0, `slice.as_ptr()` may be dangling, but this is safe
            // since the pointer is not dereferenced if the length parameter is
            // 0.
            sys::AParcel_writeCharArray(
                parcel.as_native_mut(),
                slice.as_ptr() as *const u16,
                slice.len().try_into().or(Err(StatusCode::BAD_VALUE))?,
            )
        };
        status_result(status)
    }
}

impl SerializeOption for CStr {
    fn serialize_option(this: Option<&Self>, parcel: &mut Parcel) -> Result<()> {
        match this {
            None => unsafe {
                // Safety: `Parcel` always contains a valid pointer to an
                // `AParcel`. If the string pointer is null,
                // `AParcel_writeString` requires that the length is -1 to
                // indicate that we want to serialize a null string.
                status_result(sys::AParcel_writeString(
                    parcel.as_native_mut(),
                    ptr::null(),
                    -1,
                ))
            },
            Some(s) => unsafe {
                // Safety: `Parcel` always contains a valid pointer to an
                // `AParcel`. `AParcel_writeString` assumes that we pass a
                // null-terminated C string pointer with no nulls in the middle
                // of the string. Rust guarantees exactly that for a valid CStr
                // instance.
                status_result(sys::AParcel_writeString(
                    parcel.as_native_mut(),
                    s.as_ptr(),
                    s.to_bytes()
                        .len()
                        .try_into()
                        .or(Err(StatusCode::BAD_VALUE))?,
                ))
            },
        }
    }
}

impl SerializeArray for Option<&CStr> {}

impl Serialize for CStr {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        Some(self).serialize(parcel)
    }
}

impl Serialize for CString {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        Some(self.as_c_str()).serialize(parcel)
    }
}

impl SerializeArray for CString {}

impl SerializeOption for CString {
    fn serialize_option(this: Option<&Self>, parcel: &mut Parcel) -> Result<()> {
        SerializeOption::serialize_option(this.map(CString::as_c_str), parcel)
    }
}

impl SerializeArray for Option<CString> {}

impl Serialize for String {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        Some(self.as_str()).serialize(parcel)
    }
}

impl SerializeArray for String {}

impl SerializeOption for String {
    fn serialize_option(this: Option<&Self>, parcel: &mut Parcel) -> Result<()> {
        SerializeOption::serialize_option(this.map(String::as_str), parcel)
    }
}

impl SerializeArray for Option<String> {}

impl Deserialize for Option<CString> {
    fn deserialize(parcel: &Parcel) -> Result<Self> {
        let mut vec: Option<Vec<u8>> = None;
        let status = unsafe {
            // Safety: `Parcel` always contains a valid pointer to an `AParcel`.
            // `Option<Vec<u8>>` is equivalent to the expected `Option<Vec<i8>>`
            // for `allocate_vec`, so `vec` is safe to pass as the opaque data
            // pointer on platforms where char is signed.
            sys::AParcel_readString(
                parcel.as_native(),
                &mut vec as *mut _ as *mut c_void,
                Some(allocate_vec),
            )
        };

        status_result(status)?;
        vec.map(|mut s| {
            // The vector includes a null-terminator and CString::new requires
            // no nulls, including terminating.
            s.pop();
            CString::new(s).or(Err(StatusCode::BAD_VALUE))
        })
        .transpose()
    }
}

impl DeserializeArray for Option<CString> {}

impl DeserializeOption for String {
    fn deserialize_option(parcel: &Parcel) -> Result<Option<Self>> {
        let c_str = <Option<CString>>::deserialize(parcel)?;
        c_str
            .map(|s| s.into_string().or(Err(StatusCode::BAD_VALUE)))
            .transpose()
    }
}

impl DeserializeArray for Option<String> {}

impl Deserialize for String {
    fn deserialize(parcel: &Parcel) -> Result<Self> {
        Deserialize::deserialize(parcel)
            .transpose()
            .unwrap_or(Err(StatusCode::UNEXPECTED_NULL))
    }
}

impl DeserializeArray for String {}

impl SerializeOption for str {
    fn serialize_option(this: Option<&Self>, parcel: &mut Parcel) -> Result<()> {
        match this {
            None => parcel.write(&-1i32),
            Some(s) => {
                let c_str = CString::new(s).or(Err(StatusCode::BAD_VALUE))?;
                parcel.write(&c_str)
            }
        }
    }
}

impl Serialize for str {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        Some(self).serialize(parcel)
    }
}

impl SerializeArray for &str {}

impl SerializeArray for Option<&str> {}

impl<T: SerializeArray> Serialize for [T] {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        SerializeArray::serialize_array(self, parcel)
    }
}

impl<T: SerializeArray> Serialize for Vec<T> {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        SerializeArray::serialize_array(&self[..], parcel)
    }
}

impl<T: SerializeArray> SerializeOption for [T] {
    fn serialize_option(this: Option<&Self>, parcel: &mut Parcel) -> Result<()> {
        if let Some(v) = this {
            SerializeArray::serialize_array(v, parcel)
        } else {
            parcel.write(&-1i32)
        }
    }
}

impl<T: SerializeArray> SerializeOption for Vec<T> {
    fn serialize_option(this: Option<&Self>, parcel: &mut Parcel) -> Result<()> {
        SerializeOption::serialize_option(this.map(Vec::as_slice), parcel)
    }
}

impl<T: DeserializeArray> Deserialize for Vec<T> {
    fn deserialize(parcel: &Parcel) -> Result<Self> {
        DeserializeArray::deserialize_array(parcel)
            .transpose()
            .unwrap_or(Err(StatusCode::UNEXPECTED_NULL))
    }
}

impl<T: DeserializeArray> DeserializeOption for Vec<T> {
    fn deserialize_option(parcel: &Parcel) -> Result<Option<Self>> {
        DeserializeArray::deserialize_array(parcel)
    }
}

impl Serialize for Status {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        unsafe {
            // Safety: `Parcel` always contains a valid pointer to an `AParcel`
            // and `Status` always contains a valid pointer to an `AStatus`, so
            // both parameters are valid and safe. This call does not take
            // ownership of either of its parameters.
            status_result(sys::AParcel_writeStatusHeader(
                parcel.as_native_mut(),
                self.as_native(),
            ))
        }
    }
}

impl Deserialize for Status {
    fn deserialize(parcel: &Parcel) -> Result<Self> {
        let mut status_ptr = ptr::null_mut();
        let ret_status = unsafe {
            // Safety: `Parcel` always contains a valid pointer to an
            // `AParcel`. We pass a mutable out pointer which will be
            // assigned a valid `AStatus` pointer if the function returns
            // status OK. This function passes ownership of the status
            // pointer to the caller, if it was assigned.
            sys::AParcel_readStatusHeader(parcel.as_native(), &mut status_ptr)
        };
        status_result(ret_status)?;
        Ok(unsafe {
            // Safety: At this point, the return status of the read call was ok,
            // so we know that `status_ptr` is a valid, owned pointer to an
            // `AStatus`, from which we can safely construct a `Status` object.
            Status::from_ptr(status_ptr)
        })
    }
}

impl<T: Serialize + ?Sized> Serialize for Box<T> {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        Serialize::serialize(&**self, parcel)
    }
}

impl<T: SerializeOption + ?Sized> SerializeOption for Box<T> {
    fn serialize_option(this: Option<&Self>, parcel: &mut Parcel) -> Result<()> {
        SerializeOption::serialize_option(this.map(|b| &**b), parcel)
    }
}

impl<T: FromIBinder + ?Sized> Deserialize for Box<T> {
    fn deserialize(parcel: &Parcel) -> Result<Self> {
        let ibinder: SpIBinder = parcel.read()?;
        FromIBinder::try_from(ibinder)
    }
}

impl<T: FromIBinder + ?Sized> DeserializeOption for Box<T> {
    fn deserialize_option(parcel: &Parcel) -> Result<Option<Self>> {
        let ibinder: Option<SpIBinder> = parcel.read()?;
        ibinder.map(FromIBinder::try_from).transpose()
    }
}

// We need these to support Option<&T> for all T
impl<T: Serialize + ?Sized> Serialize for &T {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        Serialize::serialize(*self, parcel)
    }
}

impl<T: SerializeOption + ?Sized> SerializeOption for &T {
    fn serialize_option(this: Option<&Self>, parcel: &mut Parcel) -> Result<()> {
        SerializeOption::serialize_option(this.copied(), parcel)
    }
}

impl<T: SerializeOption> Serialize for Option<T> {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        SerializeOption::serialize_option(self.as_ref(), parcel)
    }
}

impl<T: DeserializeOption> Deserialize for Option<T> {
    fn deserialize(parcel: &Parcel) -> Result<Self> {
        DeserializeOption::deserialize_option(parcel)
    }
}

#[test]
fn test_custom_parcelable() {
    use crate::binder::Interface;
    use crate::native::Binder;
    let mut service = Binder::new(()).as_binder();

    struct Custom(u32, bool, String, Vec<String>);

    impl Serialize for Custom {
        fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
            self.0.serialize(parcel)?;
            self.1.serialize(parcel)?;
            self.2.serialize(parcel)?;
            self.3.serialize(parcel)
        }
    }

    impl Deserialize for Custom {
        fn deserialize(parcel: &Parcel) -> Result<Self> {
            Ok(Custom(
                parcel.read()?,
                parcel.read()?,
                parcel.read()?,
                parcel.read::<Option<Vec<String>>>()?.unwrap(),
            ))
        }
    }

    let string8 = "Custom Parcelable".to_string();

    let s1 = "str1".to_string();
    let s2 = "str2".to_string();
    let s3 = "str3".to_string();

    let strs = vec![s1, s2, s3];

    let custom = Custom(123_456_789, true, string8, strs);

    let mut parcel = Parcel::new_for_test(&mut service).unwrap();
    let start = parcel.get_data_position();

    assert!(custom.serialize(&mut parcel).is_ok());

    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }

    let custom2 = Custom::deserialize(&parcel).unwrap();

    assert_eq!(custom2.0, 123_456_789);
    assert!(custom2.1);
    assert_eq!(custom2.2, custom.2);
    assert_eq!(custom2.3, custom.3);
}

#[test]
#[allow(clippy::excessive_precision)]
fn test_slice_parcelables() {
    use crate::binder::Interface;
    use crate::native::Binder;
    let mut service = Binder::new(()).as_binder();

    let bools = [true, false, false, true];

    let mut parcel = Parcel::new_for_test(&mut service).unwrap();
    let start = parcel.get_data_position();

    assert!(bools.serialize(&mut parcel).is_ok());

    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }

    assert_eq!(parcel.read::<u32>().unwrap(), 4);
    assert_eq!(parcel.read::<u32>().unwrap(), 1);
    assert_eq!(parcel.read::<u32>().unwrap(), 0);
    assert_eq!(parcel.read::<u32>().unwrap(), 0);
    assert_eq!(parcel.read::<u32>().unwrap(), 1);
    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }

    let vec = Vec::<bool>::deserialize(&parcel).unwrap();

    assert_eq!(vec, [true, false, false, true]);

    let u8s = [101u8, 255, 42, 117];

    let mut parcel = Parcel::new_for_test(&mut service).unwrap();
    let start = parcel.get_data_position();

    assert!(parcel.write(&u8s[..]).is_ok());

    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }

    assert_eq!(parcel.read::<u32>().unwrap(), 4); // 4 items
    assert_eq!(parcel.read::<u32>().unwrap(), 0x752aff65); // bytes
    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }

    let vec = Vec::<u8>::deserialize(&parcel).unwrap();
    assert_eq!(vec, [101, 255, 42, 117]);

    let i8s = [-128i8, 127, 42, -117];

    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }

    assert!(parcel.write(&i8s[..]).is_ok());

    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }

    assert_eq!(parcel.read::<u32>().unwrap(), 4); // 4 items
    assert_eq!(parcel.read::<u32>().unwrap(), 0x8b2a7f80); // bytes
    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }

    let vec = Vec::<u8>::deserialize(&parcel).unwrap();
    assert_eq!(vec, [-128i8 as u8, 127, 42, -117i8 as u8]);

    let u16s = [u16::max_value(), 12_345, 42, 117];

    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }
    assert!(u16s.serialize(&mut parcel).is_ok());
    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }

    assert_eq!(parcel.read::<u32>().unwrap(), 4); // 4 items
    assert_eq!(parcel.read::<u32>().unwrap(), 0xffff); // u16::max_value()
    assert_eq!(parcel.read::<u32>().unwrap(), 12345); // 12,345
    assert_eq!(parcel.read::<u32>().unwrap(), 42); // 42
    assert_eq!(parcel.read::<u32>().unwrap(), 117); // 117
    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }

    let vec = Vec::<u16>::deserialize(&parcel).unwrap();

    assert_eq!(vec, [u16::max_value(), 12_345, 42, 117]);

    let i16s = [i16::max_value(), i16::min_value(), 42, -117];

    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }
    assert!(i16s.serialize(&mut parcel).is_ok());
    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }

    assert_eq!(parcel.read::<u32>().unwrap(), 4); // 4 items
    assert_eq!(parcel.read::<u32>().unwrap(), 0x7fff); // i16::max_value()
    assert_eq!(parcel.read::<u32>().unwrap(), 0x8000); // i16::min_value()
    assert_eq!(parcel.read::<u32>().unwrap(), 42); // 42
    assert_eq!(parcel.read::<u32>().unwrap(), 0xff8b); // -117
    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }

    let vec = Vec::<i16>::deserialize(&parcel).unwrap();

    assert_eq!(vec, [i16::max_value(), i16::min_value(), 42, -117]);

    let u32s = [u32::max_value(), 12_345, 42, 117];

    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }
    assert!(u32s.serialize(&mut parcel).is_ok());
    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }

    assert_eq!(parcel.read::<u32>().unwrap(), 4); // 4 items
    assert_eq!(parcel.read::<u32>().unwrap(), 0xffffffff); // u32::max_value()
    assert_eq!(parcel.read::<u32>().unwrap(), 12345); // 12,345
    assert_eq!(parcel.read::<u32>().unwrap(), 42); // 42
    assert_eq!(parcel.read::<u32>().unwrap(), 117); // 117
    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }

    let vec = Vec::<u32>::deserialize(&parcel).unwrap();

    assert_eq!(vec, [u32::max_value(), 12_345, 42, 117]);

    let i32s = [i32::max_value(), i32::min_value(), 42, -117];

    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }
    assert!(i32s.serialize(&mut parcel).is_ok());
    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }

    assert_eq!(parcel.read::<u32>().unwrap(), 4); // 4 items
    assert_eq!(parcel.read::<u32>().unwrap(), 0x7fffffff); // i32::max_value()
    assert_eq!(parcel.read::<u32>().unwrap(), 0x80000000); // i32::min_value()
    assert_eq!(parcel.read::<u32>().unwrap(), 42); // 42
    assert_eq!(parcel.read::<u32>().unwrap(), 0xffffff8b); // -117
    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }

    let vec = Vec::<i32>::deserialize(&parcel).unwrap();

    assert_eq!(vec, [i32::max_value(), i32::min_value(), 42, -117]);

    let u64s = [u64::max_value(), 12_345, 42, 117];

    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }
    assert!(u64s.serialize(&mut parcel).is_ok());
    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }

    let vec = Vec::<u64>::deserialize(&parcel).unwrap();

    assert_eq!(vec, [u64::max_value(), 12_345, 42, 117]);

    let i64s = [i64::max_value(), i64::min_value(), 42, -117];

    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }
    assert!(i64s.serialize(&mut parcel).is_ok());
    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }

    let vec = Vec::<i64>::deserialize(&parcel).unwrap();

    assert_eq!(vec, [i64::max_value(), i64::min_value(), 42, -117]);

    let f32s = [
        std::f32::NAN,
        std::f32::INFINITY,
        1.23456789,
        std::f32::EPSILON,
    ];

    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }
    assert!(f32s.serialize(&mut parcel).is_ok());
    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }

    let vec = Vec::<f32>::deserialize(&parcel).unwrap();

    // NAN != NAN so we can't use it in the assert_eq:
    assert!(vec[0].is_nan());
    assert_eq!(vec[1..], f32s[1..]);

    let f64s = [
        std::f64::NAN,
        std::f64::INFINITY,
        1.234567890123456789,
        std::f64::EPSILON,
    ];

    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }
    assert!(f64s.serialize(&mut parcel).is_ok());
    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }

    let vec = Vec::<f64>::deserialize(&parcel).unwrap();

    // NAN != NAN so we can't use it in the assert_eq:
    assert!(vec[0].is_nan());
    assert_eq!(vec[1..], f64s[1..]);

    let s1 = "Hello, Binder!";
    let s2 = "This is a utf8 string.";
    let s3 = "Some more text here.";

    let strs = [s1, s2, s3];

    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }
    assert!(strs.serialize(&mut parcel).is_ok());
    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }

    let vec = Vec::<String>::deserialize(&parcel).unwrap();

    assert_eq!(vec, strs);
}
