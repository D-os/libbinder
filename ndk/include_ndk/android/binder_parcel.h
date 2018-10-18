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
 * This is called to allocate an array with a given length. If allocation fails, null should be
 * returned.
 */
typedef void* (*AParcel_arrayReallocator)(void* vectorData, size_t length);

// @START-PRIMITIVE-VECTOR-GETTERS
/**
 * This is called to get the underlying data from an arrayData object.
 *
 * This will never be called for an empty array.
 */
typedef int32_t* (*AParcel_int32ArrayGetter)(void* arrayData);

/**
 * This is called to get the underlying data from an arrayData object.
 *
 * This will never be called for an empty array.
 */
typedef uint32_t* (*AParcel_uint32ArrayGetter)(void* arrayData);

/**
 * This is called to get the underlying data from an arrayData object.
 *
 * This will never be called for an empty array.
 */
typedef int64_t* (*AParcel_int64ArrayGetter)(void* arrayData);

/**
 * This is called to get the underlying data from an arrayData object.
 *
 * This will never be called for an empty array.
 */
typedef uint64_t* (*AParcel_uint64ArrayGetter)(void* arrayData);

/**
 * This is called to get the underlying data from an arrayData object.
 *
 * This will never be called for an empty array.
 */
typedef float* (*AParcel_floatArrayGetter)(void* arrayData);

/**
 * This is called to get the underlying data from an arrayData object.
 *
 * This will never be called for an empty array.
 */
typedef double* (*AParcel_doubleArrayGetter)(void* arrayData);

/**
 * This is called to get the underlying data from an arrayData object.
 *
 * This will never be called for an empty array.
 */
typedef bool (*AParcel_boolArrayGetter)(const void* arrayData, size_t index);

/**
 * This is called to set an underlying value in an arrayData object at index.
 */
typedef void (*AParcel_boolArraySetter)(void* arrayData, size_t index, bool value);

/**
 * This is called to get the underlying data from an arrayData object.
 *
 * This will never be called for an empty array.
 */
typedef char16_t* (*AParcel_charArrayGetter)(void* arrayData);

/**
 * This is called to get the underlying data from an arrayData object.
 *
 * This will never be called for an empty array.
 */
typedef int8_t* (*AParcel_byteArrayGetter)(void* arrayData);

// @END-PRIMITIVE-VECTOR-GETTERS

/**
 * This is called to allocate a buffer
 *
 * The length here includes the space required to insert a '\0' for a properly formed c-str. If the
 * buffer returned from this function is retStr, it will be filled by AParcel_readString with the
 * data from the remote process, and it will be filled such that retStr[length] == '\0'.
 *
 * If allocation fails, null should be returned.
 */
typedef void* (*AParcel_stringReallocator)(void* stringData, size_t length);

/**
 * This is called to get the buffer from a stringData object.
 */
typedef char* (*AParcel_stringGetter)(void* stringData);

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
 * Writes string value to the next location in a non-null parcel.
 */
binder_status_t AParcel_writeString(AParcel* parcel, const char* string, size_t length)
        __INTRODUCED_IN(29);

/**
 * Reads and allocates string value from the next location in a non-null parcel.
 *
 * Data is passed to the string allocator once the string size is known. This data should be used to
 * point to some kind of string data. For instance, it could be a char*, and the string allocator
 * could be realloc. Then the getter would simply be a cast to char*. In more complicated cases,
 * stringData could be a structure containing additional string data.
 *
 * If this function returns a success, the buffer returned by allocator when passed stringData will
 * contain a null-terminated c-str read from the binder.
 */
binder_status_t AParcel_readString(const AParcel* parcel, AParcel_stringReallocator reallocator,
                                   AParcel_stringGetter getter, void** stringData)
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
 */
binder_status_t AParcel_writeBoolArray(AParcel* parcel, const void* arrayData,
                                       AParcel_boolArrayGetter getter, size_t length)
        __INTRODUCED_IN(29);

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
 */
binder_status_t AParcel_readInt32Array(const AParcel* parcel, void** arrayData,
                                       AParcel_arrayReallocator reallocator,
                                       AParcel_int32ArrayGetter getter) __INTRODUCED_IN(29);

/**
 * Reads an array of uint32_t from the next location in a non-null parcel.
 */
binder_status_t AParcel_readUint32Array(const AParcel* parcel, void** arrayData,
                                        AParcel_arrayReallocator reallocator,
                                        AParcel_uint32ArrayGetter getter) __INTRODUCED_IN(29);

/**
 * Reads an array of int64_t from the next location in a non-null parcel.
 */
binder_status_t AParcel_readInt64Array(const AParcel* parcel, void** arrayData,
                                       AParcel_arrayReallocator reallocator,
                                       AParcel_int64ArrayGetter getter) __INTRODUCED_IN(29);

/**
 * Reads an array of uint64_t from the next location in a non-null parcel.
 */
binder_status_t AParcel_readUint64Array(const AParcel* parcel, void** arrayData,
                                        AParcel_arrayReallocator reallocator,
                                        AParcel_uint64ArrayGetter getter) __INTRODUCED_IN(29);

/**
 * Reads an array of float from the next location in a non-null parcel.
 */
binder_status_t AParcel_readFloatArray(const AParcel* parcel, void** arrayData,
                                       AParcel_arrayReallocator reallocator,
                                       AParcel_floatArrayGetter getter) __INTRODUCED_IN(29);

/**
 * Reads an array of double from the next location in a non-null parcel.
 */
binder_status_t AParcel_readDoubleArray(const AParcel* parcel, void** arrayData,
                                        AParcel_arrayReallocator reallocator,
                                        AParcel_doubleArrayGetter getter) __INTRODUCED_IN(29);

/**
 * Reads an array of bool from the next location in a non-null parcel.
 */
binder_status_t AParcel_readBoolArray(const AParcel* parcel, void** arrayData,
                                      AParcel_arrayReallocator reallocator,
                                      AParcel_boolArraySetter setter) __INTRODUCED_IN(29);

/**
 * Reads an array of char16_t from the next location in a non-null parcel.
 */
binder_status_t AParcel_readCharArray(const AParcel* parcel, void** arrayData,
                                      AParcel_arrayReallocator reallocator,
                                      AParcel_charArrayGetter getter) __INTRODUCED_IN(29);

/**
 * Reads an array of int8_t from the next location in a non-null parcel.
 */
binder_status_t AParcel_readByteArray(const AParcel* parcel, void** arrayData,
                                      AParcel_arrayReallocator reallocator,
                                      AParcel_byteArrayGetter getter) __INTRODUCED_IN(29);

// @END-PRIMITIVE-READ-WRITE

#endif //__ANDROID_API__ >= __ANDROID_API_Q__
__END_DECLS

/** @} */
