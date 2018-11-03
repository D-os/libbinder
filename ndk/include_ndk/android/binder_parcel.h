/*
 * Copyright (C) 2018 The Android Open Source Project
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

/**
 * @addtogroup NdkBinder
 * @{
 */

/**
 * @file binder_parcel.h
 * @brief A collection of data that can be sent as a single packet.
 */

#pragma once

#include <sys/cdefs.h>

#include <android/binder_status.h>

struct AIBinder;
typedef struct AIBinder AIBinder;

__BEGIN_DECLS
#if __ANDROID_API__ >= __ANDROID_API_Q__

/**
 * This object represents a package of data that can be sent between processes. When transacting, an
 * instance of it is automatically created to be used for the transaction. When two processes use
 * binder to communicate, they must agree on a format of this parcel to be used in order to transfer
 * data. This is usually done in an IDL (see AIDL, specificially).
 */
struct AParcel;
typedef struct AParcel AParcel;

/**
 * Cleans up a parcel.
 */
void AParcel_delete(AParcel* parcel) __INTRODUCED_IN(29);

/**
 * This is called to allocate a buffer for a C-style string (null-terminated). The returned buffer
 * should be at least length bytes. This includes space for a null terminator. length will always be
 * strictly less than or equal to the maximum size that can be held in a size_t and will always be
 * greater than 0.
 *
 * See also AParcel_readString.
 *
 * If allocation fails, null should be returned.
 */
typedef char* (*AParcel_stringAllocator)(void* stringData, size_t length);

/**
 * This is called to allocate an array of size 'length'.
 *
 * See also AParcel_readStringArray
 */
typedef bool (*AParcel_stringArrayAllocator)(void* arrayData, size_t length);

/**
 * This is called to allocate a string inside of an array that was allocated by an
 * AParcel_stringArrayAllocator.
 *
 * The index returned will always be within the range [0, length of arrayData). The returned buffer
 * should be at least length bytes. This includes space for a null-terminator. length will always be
 * strictly less than or equal to the maximum size that can be held in a size_t and will always be
 * greater than 0.
 *
 * See also AParcel_readStringArray
 */
typedef char* (*AParcel_stringArrayElementAllocator)(void* arrayData, size_t index, size_t length);

/**
 * This returns the length and buffer of an array at a specific index in an arrayData object.
 *
 * See also AParcel_writeStringArray
 */
typedef const char* (*AParcel_stringArrayElementGetter)(const void* arrayData, size_t index,
                                                        size_t* outLength);

// @START-PRIMITIVE-VECTOR-GETTERS
/**
 * This is called to get the underlying data from an arrayData object.
 *
 * The implementation of this function should allocate a contiguous array of size 'length' and
 * return that underlying buffer to be filled out. If there is an error or length is 0, null may be
 * returned.
 *
 * See also AParcel_readInt32Array
 */
typedef int32_t* (*AParcel_int32ArrayAllocator)(void* arrayData, size_t length);

/**
 * This is called to get the underlying data from an arrayData object.
 *
 * The implementation of this function should allocate a contiguous array of size 'length' and
 * return that underlying buffer to be filled out. If there is an error or length is 0, null may be
 * returned.
 *
 * See also AParcel_readUint32Array
 */
typedef uint32_t* (*AParcel_uint32ArrayAllocator)(void* arrayData, size_t length);

/**
 * This is called to get the underlying data from an arrayData object.
 *
 * The implementation of this function should allocate a contiguous array of size 'length' and
 * return that underlying buffer to be filled out. If there is an error or length is 0, null may be
 * returned.
 *
 * See also AParcel_readInt64Array
 */
typedef int64_t* (*AParcel_int64ArrayAllocator)(void* arrayData, size_t length);

/**
 * This is called to get the underlying data from an arrayData object.
 *
 * The implementation of this function should allocate a contiguous array of size 'length' and
 * return that underlying buffer to be filled out. If there is an error or length is 0, null may be
 * returned.
 *
 * See also AParcel_readUint64Array
 */
typedef uint64_t* (*AParcel_uint64ArrayAllocator)(void* arrayData, size_t length);

/**
 * This is called to get the underlying data from an arrayData object.
 *
 * The implementation of this function should allocate a contiguous array of size 'length' and
 * return that underlying buffer to be filled out. If there is an error or length is 0, null may be
 * returned.
 *
 * See also AParcel_readFloatArray
 */
typedef float* (*AParcel_floatArrayAllocator)(void* arrayData, size_t length);

/**
 * This is called to get the underlying data from an arrayData object.
 *
 * The implementation of this function should allocate a contiguous array of size 'length' and
 * return that underlying buffer to be filled out. If there is an error or length is 0, null may be
 * returned.
 *
 * See also AParcel_readDoubleArray
 */
typedef double* (*AParcel_doubleArrayAllocator)(void* arrayData, size_t length);

/**
 * This allocates an array of size 'length' inside of arrayData and returns whether or not there was
 * a success.
 *
 * See also AParcel_readBoolArray
 */
typedef bool (*AParcel_boolArrayAllocator)(void* arrayData, size_t length);

/**
 * This is called to get the underlying data from an arrayData object at index.
 *
 * See also AParcel_writeBoolArray
 */
typedef bool (*AParcel_boolArrayGetter)(const void* arrayData, size_t index);

/**
 * This is called to set an underlying value in an arrayData object at index.
 *
 * See also AParcel_readBoolArray
 */
typedef void (*AParcel_boolArraySetter)(void* arrayData, size_t index, bool value);

/**
 * This is called to get the underlying data from an arrayData object.
 *
 * The implementation of this function should allocate a contiguous array of size 'length' and
 * return that underlying buffer to be filled out. If there is an error or length is 0, null may be
 * returned.
 *
 * See also AParcel_readCharArray
 */
typedef char16_t* (*AParcel_charArrayAllocator)(void* arrayData, size_t length);

/**
 * This is called to get the underlying data from an arrayData object.
 *
 * The implementation of this function should allocate a contiguous array of size 'length' and
 * return that underlying buffer to be filled out. If there is an error or length is 0, null may be
 * returned.
 *
 * See also AParcel_readByteArray
 */
typedef int8_t* (*AParcel_byteArrayAllocator)(void* arrayData, size_t length);

// @END-PRIMITIVE-VECTOR-GETTERS

/**
 * Writes an AIBinder to the next location in a non-null parcel. Can be null.
 */
binder_status_t AParcel_writeStrongBinder(AParcel* parcel, AIBinder* binder) __INTRODUCED_IN(29);

/**
 * Reads an AIBinder from the next location in a non-null parcel. This will fail if the binder is
 * non-null. One strong ref-count of ownership is passed to the caller of this function.
 */
binder_status_t AParcel_readStrongBinder(const AParcel* parcel, AIBinder** binder)
        __INTRODUCED_IN(29);

/**
 * Reads an AIBinder from the next location in a non-null parcel. This may read a null. One strong
 * ref-count of ownership is passed to the caller of this function.
 */
binder_status_t AParcel_readNullableStrongBinder(const AParcel* parcel, AIBinder** binder)
        __INTRODUCED_IN(29);

/**
 * Writes a file descriptor to the next location in a non-null parcel. This does not take ownership
 * of fd.
 *
 * This corresponds to the SDK's android.os.ParcelFileDescriptor.
 */
binder_status_t AParcel_writeParcelFileDescriptor(AParcel* parcel, int fd);

/**
 * Reads an int from the next location in a non-null parcel.
 *
 * The returned fd must be closed.
 *
 * This corresponds to the SDK's android.os.ParcelFileDescriptor.
 */
binder_status_t AParcel_readParcelFileDescriptor(const AParcel* parcel, int* fd);

/**
 * Writes an AStatus object to the next location in a non-null parcel.
 *
 * If the status is considered to be a low-level status and has no additional information other
 * than a binder_status_t (for instance, if it is created with AStatus_fromStatus), then that
 * status will be returned from this method and nothing will be written to the parcel. If either
 * this happens or if writing the status object itself fails, the return value from this function
 * should be propagated to the client, and AParcel_readStatusHeader shouldn't be called.
 */
binder_status_t AParcel_writeStatusHeader(AParcel* parcel, const AStatus* status)
        __INTRODUCED_IN(29);

/**
 * Reads an AStatus from the next location in a non-null parcel. Ownership is passed to the caller
 * of this function.
 */
binder_status_t AParcel_readStatusHeader(const AParcel* parcel, AStatus** status)
        __INTRODUCED_IN(29);

/**
 * Writes utf-8 string value to the next location in a non-null parcel.
 */
binder_status_t AParcel_writeString(AParcel* parcel, const char* string, size_t length)
        __INTRODUCED_IN(29);

/**
 * Reads and allocates utf-8 string value from the next location in a non-null parcel.
 *
 * Data is passed to the string allocator once the string size is known. This size includes the
 * space for the null-terminator of this string. This allocator returns a buffer which is used as
 * the output buffer from this read.
 */
binder_status_t AParcel_readString(const AParcel* parcel, void* stringData,
                                   AParcel_stringAllocator allocator) __INTRODUCED_IN(29);

/**
 * Writes utf-8 string array data to the next location in a non-null parcel.
 *
 * length is the length of the array. AParcel_stringArrayElementGetter will be called for all
 * indices in range [0, length) with the arrayData provided here. The string length and buffer
 * returned from this function will be used to fill out the data from the parcel.
 */
binder_status_t AParcel_writeStringArray(AParcel* parcel, const void* arrayData, size_t length,
                                         AParcel_stringArrayElementGetter getter)
        __INTRODUCED_IN(29);

/**
 * Reads and allocates utf-8 string array value from the next location in a non-null parcel.
 *
 * First, AParcel_stringArrayAllocator will be called with the size of the array to be read where
 * length is the length of the array to be read from the parcel. Then, for each index i in [0,
 * length), AParcel_stringArrayElementAllocator will be called with the length of the string to be
 * read from the parcel. The resultant buffer from each of these calls will be filled according to
 * the contents of the string that is read.
 */
binder_status_t AParcel_readStringArray(const AParcel* parcel, void* arrayData,
                                        AParcel_stringArrayAllocator allocator,
                                        AParcel_stringArrayElementAllocator elementAllocator)
        __INTRODUCED_IN(29);

// @START-PRIMITIVE-READ-WRITE
/**
 * Writes int32_t value to the next location in a non-null parcel.
 */
binder_status_t AParcel_writeInt32(AParcel* parcel, int32_t value) __INTRODUCED_IN(29);

/**
 * Writes uint32_t value to the next location in a non-null parcel.
 */
binder_status_t AParcel_writeUint32(AParcel* parcel, uint32_t value) __INTRODUCED_IN(29);

/**
 * Writes int64_t value to the next location in a non-null parcel.
 */
binder_status_t AParcel_writeInt64(AParcel* parcel, int64_t value) __INTRODUCED_IN(29);

/**
 * Writes uint64_t value to the next location in a non-null parcel.
 */
binder_status_t AParcel_writeUint64(AParcel* parcel, uint64_t value) __INTRODUCED_IN(29);

/**
 * Writes float value to the next location in a non-null parcel.
 */
binder_status_t AParcel_writeFloat(AParcel* parcel, float value) __INTRODUCED_IN(29);

/**
 * Writes double value to the next location in a non-null parcel.
 */
binder_status_t AParcel_writeDouble(AParcel* parcel, double value) __INTRODUCED_IN(29);

/**
 * Writes bool value to the next location in a non-null parcel.
 */
binder_status_t AParcel_writeBool(AParcel* parcel, bool value) __INTRODUCED_IN(29);

/**
 * Writes char16_t value to the next location in a non-null parcel.
 */
binder_status_t AParcel_writeChar(AParcel* parcel, char16_t value) __INTRODUCED_IN(29);

/**
 * Writes int8_t value to the next location in a non-null parcel.
 */
binder_status_t AParcel_writeByte(AParcel* parcel, int8_t value) __INTRODUCED_IN(29);

/**
 * Reads into int32_t value from the next location in a non-null parcel.
 */
binder_status_t AParcel_readInt32(const AParcel* parcel, int32_t* value) __INTRODUCED_IN(29);

/**
 * Reads into uint32_t value from the next location in a non-null parcel.
 */
binder_status_t AParcel_readUint32(const AParcel* parcel, uint32_t* value) __INTRODUCED_IN(29);

/**
 * Reads into int64_t value from the next location in a non-null parcel.
 */
binder_status_t AParcel_readInt64(const AParcel* parcel, int64_t* value) __INTRODUCED_IN(29);

/**
 * Reads into uint64_t value from the next location in a non-null parcel.
 */
binder_status_t AParcel_readUint64(const AParcel* parcel, uint64_t* value) __INTRODUCED_IN(29);

/**
 * Reads into float value from the next location in a non-null parcel.
 */
binder_status_t AParcel_readFloat(const AParcel* parcel, float* value) __INTRODUCED_IN(29);

/**
 * Reads into double value from the next location in a non-null parcel.
 */
binder_status_t AParcel_readDouble(const AParcel* parcel, double* value) __INTRODUCED_IN(29);

/**
 * Reads into bool value from the next location in a non-null parcel.
 */
binder_status_t AParcel_readBool(const AParcel* parcel, bool* value) __INTRODUCED_IN(29);

/**
 * Reads into char16_t value from the next location in a non-null parcel.
 */
binder_status_t AParcel_readChar(const AParcel* parcel, char16_t* value) __INTRODUCED_IN(29);

/**
 * Reads into int8_t value from the next location in a non-null parcel.
 */
binder_status_t AParcel_readByte(const AParcel* parcel, int8_t* value) __INTRODUCED_IN(29);

/**
 * Writes an array of int32_t to the next location in a non-null parcel.
 */
binder_status_t AParcel_writeInt32Array(AParcel* parcel, const int32_t* value, size_t length)
        __INTRODUCED_IN(29);

/**
 * Writes an array of uint32_t to the next location in a non-null parcel.
 */
binder_status_t AParcel_writeUint32Array(AParcel* parcel, const uint32_t* value, size_t length)
        __INTRODUCED_IN(29);

/**
 * Writes an array of int64_t to the next location in a non-null parcel.
 */
binder_status_t AParcel_writeInt64Array(AParcel* parcel, const int64_t* value, size_t length)
        __INTRODUCED_IN(29);

/**
 * Writes an array of uint64_t to the next location in a non-null parcel.
 */
binder_status_t AParcel_writeUint64Array(AParcel* parcel, const uint64_t* value, size_t length)
        __INTRODUCED_IN(29);

/**
 * Writes an array of float to the next location in a non-null parcel.
 */
binder_status_t AParcel_writeFloatArray(AParcel* parcel, const float* value, size_t length)
        __INTRODUCED_IN(29);

/**
 * Writes an array of double to the next location in a non-null parcel.
 */
binder_status_t AParcel_writeDoubleArray(AParcel* parcel, const double* value, size_t length)
        __INTRODUCED_IN(29);

/**
 * Writes an array of bool to the next location in a non-null parcel.
 *
 * getter(arrayData, i) will be called for each i in [0, length) in order to get the underlying
 * values to write to the parcel.
 */
binder_status_t AParcel_writeBoolArray(AParcel* parcel, const void* arrayData, size_t length,
                                       AParcel_boolArrayGetter getter) __INTRODUCED_IN(29);

/**
 * Writes an array of char16_t to the next location in a non-null parcel.
 */
binder_status_t AParcel_writeCharArray(AParcel* parcel, const char16_t* value, size_t length)
        __INTRODUCED_IN(29);

/**
 * Writes an array of int8_t to the next location in a non-null parcel.
 */
binder_status_t AParcel_writeByteArray(AParcel* parcel, const int8_t* value, size_t length)
        __INTRODUCED_IN(29);

/**
 * Reads an array of int32_t from the next location in a non-null parcel.
 *
 * First, allocator will be called with the length of the array. If the allocation succeeds and the
 * length is greater than zero, the buffer returned by the allocator will be filled with the
 * corresponding data
 */
binder_status_t AParcel_readInt32Array(const AParcel* parcel, void* arrayData,
                                       AParcel_int32ArrayAllocator allocator) __INTRODUCED_IN(29);

/**
 * Reads an array of uint32_t from the next location in a non-null parcel.
 *
 * First, allocator will be called with the length of the array. If the allocation succeeds and the
 * length is greater than zero, the buffer returned by the allocator will be filled with the
 * corresponding data
 */
binder_status_t AParcel_readUint32Array(const AParcel* parcel, void* arrayData,
                                        AParcel_uint32ArrayAllocator allocator) __INTRODUCED_IN(29);

/**
 * Reads an array of int64_t from the next location in a non-null parcel.
 *
 * First, allocator will be called with the length of the array. If the allocation succeeds and the
 * length is greater than zero, the buffer returned by the allocator will be filled with the
 * corresponding data
 */
binder_status_t AParcel_readInt64Array(const AParcel* parcel, void* arrayData,
                                       AParcel_int64ArrayAllocator allocator) __INTRODUCED_IN(29);

/**
 * Reads an array of uint64_t from the next location in a non-null parcel.
 *
 * First, allocator will be called with the length of the array. If the allocation succeeds and the
 * length is greater than zero, the buffer returned by the allocator will be filled with the
 * corresponding data
 */
binder_status_t AParcel_readUint64Array(const AParcel* parcel, void* arrayData,
                                        AParcel_uint64ArrayAllocator allocator) __INTRODUCED_IN(29);

/**
 * Reads an array of float from the next location in a non-null parcel.
 *
 * First, allocator will be called with the length of the array. If the allocation succeeds and the
 * length is greater than zero, the buffer returned by the allocator will be filled with the
 * corresponding data
 */
binder_status_t AParcel_readFloatArray(const AParcel* parcel, void* arrayData,
                                       AParcel_floatArrayAllocator allocator) __INTRODUCED_IN(29);

/**
 * Reads an array of double from the next location in a non-null parcel.
 *
 * First, allocator will be called with the length of the array. If the allocation succeeds and the
 * length is greater than zero, the buffer returned by the allocator will be filled with the
 * corresponding data
 */
binder_status_t AParcel_readDoubleArray(const AParcel* parcel, void* arrayData,
                                        AParcel_doubleArrayAllocator allocator) __INTRODUCED_IN(29);

/**
 * Reads an array of bool from the next location in a non-null parcel.
 *
 * First, allocator will be called with the length of the array. Then, for every i in [0, length),
 * setter(arrayData, i, x) will be called where x is the value at the associated index.
 */
binder_status_t AParcel_readBoolArray(const AParcel* parcel, void* arrayData,
                                      AParcel_boolArrayAllocator allocator,
                                      AParcel_boolArraySetter setter) __INTRODUCED_IN(29);

/**
 * Reads an array of char16_t from the next location in a non-null parcel.
 *
 * First, allocator will be called with the length of the array. If the allocation succeeds and the
 * length is greater than zero, the buffer returned by the allocator will be filled with the
 * corresponding data
 */
binder_status_t AParcel_readCharArray(const AParcel* parcel, void* arrayData,
                                      AParcel_charArrayAllocator allocator) __INTRODUCED_IN(29);

/**
 * Reads an array of int8_t from the next location in a non-null parcel.
 *
 * First, allocator will be called with the length of the array. If the allocation succeeds and the
 * length is greater than zero, the buffer returned by the allocator will be filled with the
 * corresponding data
 */
binder_status_t AParcel_readByteArray(const AParcel* parcel, void* arrayData,
                                      AParcel_byteArrayAllocator allocator) __INTRODUCED_IN(29);

// @END-PRIMITIVE-READ-WRITE

#endif  //__ANDROID_API__ >= __ANDROID_API_Q__
__END_DECLS

/** @} */
