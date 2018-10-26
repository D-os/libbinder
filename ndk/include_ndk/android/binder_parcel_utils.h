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
 * This resizes a std::vector of some underlying type to the given length.
 */
template <typename T>
static inline void* AParcel_stdVectorReallocator(void* vectorData, size_t length) {
    std::vector<T>* vec = static_cast<std::vector<T>*>(vectorData);
    if (length > vec->max_size()) return nullptr;

    vec->resize(length);
    return vec;
}

/**
 * This retrieves the underlying contiguous vector from a corresponding vectorData.
 */
template <typename T>
static inline T* AParcel_stdVectorGetter(void* vectorData) {
    std::vector<T>* vec = static_cast<std::vector<T>*>(vectorData);
    return vec->data();
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
    return AParcel_readInt32Array(parcel, &vectorData, &AParcel_stdVectorReallocator<int32_t>,
                                  AParcel_stdVectorGetter<int32_t>);
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
    return AParcel_readUint32Array(parcel, &vectorData, &AParcel_stdVectorReallocator<uint32_t>,
                                   AParcel_stdVectorGetter<uint32_t>);
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
    return AParcel_readInt64Array(parcel, &vectorData, &AParcel_stdVectorReallocator<int64_t>,
                                  AParcel_stdVectorGetter<int64_t>);
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
    return AParcel_readUint64Array(parcel, &vectorData, &AParcel_stdVectorReallocator<uint64_t>,
                                   AParcel_stdVectorGetter<uint64_t>);
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
    return AParcel_readFloatArray(parcel, &vectorData, &AParcel_stdVectorReallocator<float>,
                                  AParcel_stdVectorGetter<float>);
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
    return AParcel_readDoubleArray(parcel, &vectorData, &AParcel_stdVectorReallocator<double>,
                                   AParcel_stdVectorGetter<double>);
}

/**
 * Writes a vector of bool to the next location in a non-null parcel.
 */
inline binder_status_t AParcel_writeVector(AParcel* parcel, const std::vector<bool>& vec) {
    return AParcel_writeBoolArray(parcel, static_cast<const void*>(&vec),
                                  AParcel_stdVectorGetter<bool>, vec.size());
}

/**
 * Reads a vector of bool from the next location in a non-null parcel.
 */
inline binder_status_t AParcel_readVector(const AParcel* parcel, std::vector<bool>* vec) {
    void* vectorData = static_cast<void*>(vec);
    return AParcel_readBoolArray(parcel, &vectorData, &AParcel_stdVectorReallocator<bool>,
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
    return AParcel_readCharArray(parcel, &vectorData, &AParcel_stdVectorReallocator<char16_t>,
                                 AParcel_stdVectorGetter<char16_t>);
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
    return AParcel_readByteArray(parcel, &vectorData, &AParcel_stdVectorReallocator<int8_t>,
                                 AParcel_stdVectorGetter<int8_t>);
}

// @END

/**
 * Takes a std::string and reallocates it to the specified length. For use with AParcel_readString.
 * See use below in AParcel_readString.
 */
static inline void* AParcel_stdStringReallocator(void* stringData, size_t length) {
    std::string* str = static_cast<std::string*>(stringData);
    str->resize(length - 1);
    return stringData;
}

/**
 * Takes a std::string and returns the inner char*.
 */
static inline char* AParcel_stdStringGetter(void* stringData) {
    std::string* str = static_cast<std::string*>(stringData);
    return &(*str)[0];
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
    return AParcel_readString(parcel, AParcel_stdStringReallocator, AParcel_stdStringGetter,
                              &stringData);
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

} // namespace ndk

#endif // __cplusplus

/** @} */
