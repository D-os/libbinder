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
 * @file binder_parcel_utils.h
 * @brief A collection of helper wrappers for AParcel.
 */

#pragma once

#include <android/binder_parcel.h>

#ifdef __cplusplus

#include <string>
#include <vector>

namespace ndk {

/**
 * This retrieves and allocates a vector to size 'length' and returns the underlying buffer.
 */
template <typename T>
static inline T* AParcel_stdVectorAllocator(void* vectorData, size_t length) {
    std::vector<T>* vec = static_cast<std::vector<T>*>(vectorData);
    if (length > vec->max_size()) return nullptr;

    vec->resize(length);
    return vec->data();
}

/**
 * This allocates a vector to size 'length' and returns whether the allocation is successful.
 *
 * See also AParcel_stdVectorAllocator. Types used with this allocator have their sizes defined
 * externally with respect to the NDK, and that size information is not passed into the NDK.
 * Instead, it is used in cases where callbacks are used.
 *
 * See AParcel_readVector(const AParcel* parcel, std::vector<bool>)
 * See AParcel_readVector(const AParcel* parcel, std::vector<std::string>)
 */
template <typename T>
static inline bool AParcel_stdVectorExternalAllocator(void* vectorData, size_t length) {
    std::vector<T>* vec = static_cast<std::vector<T>*>(vectorData);
    if (length > vec->max_size()) return false;

    vec->resize(length);
    return true;
}

/**
 * This retrieves the underlying value in a vector which may not be contiguous at index from a
 * corresponding vectorData.
 */
template <typename T>
static inline T AParcel_stdVectorGetter(const void* vectorData, size_t index) {
    const std::vector<T>* vec = static_cast<const std::vector<T>*>(vectorData);
    return (*vec)[index];
}

/**
 * This sets the underlying value in a corresponding vectorData which may not be contiguous at
 * index.
 */
template <typename T>
static inline void AParcel_stdVectorSetter(void* vectorData, size_t index, T value) {
    std::vector<T>* vec = static_cast<std::vector<T>*>(vectorData);
    (*vec)[index] = value;
}

// @START
/**
 * Writes a vector of int32_t to the next location in a non-null parcel.
 */
inline binder_status_t AParcel_writeVector(AParcel* parcel, const std::vector<int32_t>& vec) {
    return AParcel_writeInt32Array(parcel, vec.data(), vec.size());
}

/**
 * Reads a vector of int32_t from the next location in a non-null parcel.
 */
inline binder_status_t AParcel_readVector(const AParcel* parcel, std::vector<int32_t>* vec) {
    void* vectorData = static_cast<void*>(vec);
    return AParcel_readInt32Array(parcel, vectorData, AParcel_stdVectorAllocator<int32_t>);
}

/**
 * Writes a vector of uint32_t to the next location in a non-null parcel.
 */
inline binder_status_t AParcel_writeVector(AParcel* parcel, const std::vector<uint32_t>& vec) {
    return AParcel_writeUint32Array(parcel, vec.data(), vec.size());
}

/**
 * Reads a vector of uint32_t from the next location in a non-null parcel.
 */
inline binder_status_t AParcel_readVector(const AParcel* parcel, std::vector<uint32_t>* vec) {
    void* vectorData = static_cast<void*>(vec);
    return AParcel_readUint32Array(parcel, vectorData, AParcel_stdVectorAllocator<uint32_t>);
}

/**
 * Writes a vector of int64_t to the next location in a non-null parcel.
 */
inline binder_status_t AParcel_writeVector(AParcel* parcel, const std::vector<int64_t>& vec) {
    return AParcel_writeInt64Array(parcel, vec.data(), vec.size());
}

/**
 * Reads a vector of int64_t from the next location in a non-null parcel.
 */
inline binder_status_t AParcel_readVector(const AParcel* parcel, std::vector<int64_t>* vec) {
    void* vectorData = static_cast<void*>(vec);
    return AParcel_readInt64Array(parcel, vectorData, AParcel_stdVectorAllocator<int64_t>);
}

/**
 * Writes a vector of uint64_t to the next location in a non-null parcel.
 */
inline binder_status_t AParcel_writeVector(AParcel* parcel, const std::vector<uint64_t>& vec) {
    return AParcel_writeUint64Array(parcel, vec.data(), vec.size());
}

/**
 * Reads a vector of uint64_t from the next location in a non-null parcel.
 */
inline binder_status_t AParcel_readVector(const AParcel* parcel, std::vector<uint64_t>* vec) {
    void* vectorData = static_cast<void*>(vec);
    return AParcel_readUint64Array(parcel, vectorData, AParcel_stdVectorAllocator<uint64_t>);
}

/**
 * Writes a vector of float to the next location in a non-null parcel.
 */
inline binder_status_t AParcel_writeVector(AParcel* parcel, const std::vector<float>& vec) {
    return AParcel_writeFloatArray(parcel, vec.data(), vec.size());
}

/**
 * Reads a vector of float from the next location in a non-null parcel.
 */
inline binder_status_t AParcel_readVector(const AParcel* parcel, std::vector<float>* vec) {
    void* vectorData = static_cast<void*>(vec);
    return AParcel_readFloatArray(parcel, vectorData, AParcel_stdVectorAllocator<float>);
}

/**
 * Writes a vector of double to the next location in a non-null parcel.
 */
inline binder_status_t AParcel_writeVector(AParcel* parcel, const std::vector<double>& vec) {
    return AParcel_writeDoubleArray(parcel, vec.data(), vec.size());
}

/**
 * Reads a vector of double from the next location in a non-null parcel.
 */
inline binder_status_t AParcel_readVector(const AParcel* parcel, std::vector<double>* vec) {
    void* vectorData = static_cast<void*>(vec);
    return AParcel_readDoubleArray(parcel, vectorData, AParcel_stdVectorAllocator<double>);
}

/**
 * Writes a vector of bool to the next location in a non-null parcel.
 */
inline binder_status_t AParcel_writeVector(AParcel* parcel, const std::vector<bool>& vec) {
    return AParcel_writeBoolArray(parcel, static_cast<const void*>(&vec), vec.size(),
                                  AParcel_stdVectorGetter<bool>);
}

/**
 * Reads a vector of bool from the next location in a non-null parcel.
 */
inline binder_status_t AParcel_readVector(const AParcel* parcel, std::vector<bool>* vec) {
    void* vectorData = static_cast<void*>(vec);
    return AParcel_readBoolArray(parcel, vectorData, AParcel_stdVectorExternalAllocator<bool>,
                                 AParcel_stdVectorSetter<bool>);
}

/**
 * Writes a vector of char16_t to the next location in a non-null parcel.
 */
inline binder_status_t AParcel_writeVector(AParcel* parcel, const std::vector<char16_t>& vec) {
    return AParcel_writeCharArray(parcel, vec.data(), vec.size());
}

/**
 * Reads a vector of char16_t from the next location in a non-null parcel.
 */
inline binder_status_t AParcel_readVector(const AParcel* parcel, std::vector<char16_t>* vec) {
    void* vectorData = static_cast<void*>(vec);
    return AParcel_readCharArray(parcel, vectorData, AParcel_stdVectorAllocator<char16_t>);
}

/**
 * Writes a vector of int8_t to the next location in a non-null parcel.
 */
inline binder_status_t AParcel_writeVector(AParcel* parcel, const std::vector<int8_t>& vec) {
    return AParcel_writeByteArray(parcel, vec.data(), vec.size());
}

/**
 * Reads a vector of int8_t from the next location in a non-null parcel.
 */
inline binder_status_t AParcel_readVector(const AParcel* parcel, std::vector<int8_t>* vec) {
    void* vectorData = static_cast<void*>(vec);
    return AParcel_readByteArray(parcel, vectorData, AParcel_stdVectorAllocator<int8_t>);
}

// @END

/**
 * Allocates a std::string to length and returns the underlying buffer. For use with
 * AParcel_readString. See use below in AParcel_readString(const AParcel*, std::string*).
 */
static inline char* AParcel_stdStringAllocator(void* stringData, size_t length) {
    std::string* str = static_cast<std::string*>(stringData);
    str->resize(length - 1);
    return &(*str)[0];
}

/**
 * Allocates a std::string inside of a std::vector<std::string> at index index to size 'length'.
 */
static inline char* AParcel_stdVectorStringElementAllocator(void* vectorData, size_t index,
                                                            size_t length) {
    std::vector<std::string>* vec = static_cast<std::vector<std::string>*>(vectorData);

    std::string& element = vec->at(index);
    element.resize(length - 1);
    return &element[0];
}

/**
 * This gets the length and buffer of a std::string inside of a std::vector<std::string> at index
 * index.
 */
static inline const char* AParcel_stdVectorStringElementGetter(const void* vectorData, size_t index,
                                                               size_t* outLength) {
    const std::vector<std::string>* vec = static_cast<const std::vector<std::string>*>(vectorData);

    const std::string& element = vec->at(index);

    *outLength = element.size();
    return element.c_str();
}

/**
 * Convenience API for writing a std::string.
 */
static inline binder_status_t AParcel_writeString(AParcel* parcel, const std::string& str) {
    return AParcel_writeString(parcel, str.c_str(), str.size());
}

/**
 * Convenience API for reading a std::string.
 */
static inline binder_status_t AParcel_readString(const AParcel* parcel, std::string* str) {
    void* stringData = static_cast<void*>(str);
    return AParcel_readString(parcel, stringData, AParcel_stdStringAllocator);
}

/**
 * Convenience API for writing a std::vector<std::string>
 */
static inline binder_status_t AParcel_writeVector(AParcel* parcel,
                                                  const std::vector<std::string>& vec) {
    const void* vectorData = static_cast<const void*>(&vec);
    return AParcel_writeStringArray(parcel, vectorData, vec.size(),
                                    AParcel_stdVectorStringElementGetter);
}

/**
 * Convenience API for reading a std::vector<std::string>
 */
static inline binder_status_t AParcel_readVector(const AParcel* parcel,
                                                 std::vector<std::string>* vec) {
    void* vectorData = static_cast<void*>(vec);
    return AParcel_readStringArray(parcel, vectorData,
                                   AParcel_stdVectorExternalAllocator<std::string>,
                                   AParcel_stdVectorStringElementAllocator);
}

template <typename T>
static inline binder_status_t AParcel_writeVectorSize(AParcel* parcel, const std::vector<T>& vec) {
    if (vec.size() > INT32_MAX) {
        return STATUS_BAD_VALUE;
    }

    return AParcel_writeInt32(parcel, static_cast<int32_t>(vec.size()));
}

template <typename T>
static inline binder_status_t AParcel_resizeVector(const AParcel* parcel, std::vector<T>* vec) {
    int32_t size;
    binder_status_t err = AParcel_readInt32(parcel, &size);

    if (err != STATUS_OK) return err;
    if (size < 0) return STATUS_UNEXPECTED_NULL;

    vec->resize(static_cast<size_t>(size));
    return STATUS_OK;
}

}  // namespace ndk

#endif  // __cplusplus

/** @} */
