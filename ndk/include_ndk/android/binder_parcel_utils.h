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

namespace ndk {

/**
 * Takes a std::string and reallocates it to the specified length. For use with AParcel_readString.
 * See use below in AParcel_readString.
 */
static inline void* AParcel_std_string_reallocator(void* stringData, size_t length) {
    std::string* str = static_cast<std::string*>(stringData);
    str->resize(length - 1);
    return stringData;
}

/**
 * Takes a std::string and returns the inner char*.
 */
static inline char* AParcel_std_string_getter(void* stringData) {
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
    return AParcel_readString(parcel, AParcel_std_string_reallocator, AParcel_std_string_getter,
                              &stringData);
}

} // namespace ndk

#endif // __cplusplus

/** @} */
