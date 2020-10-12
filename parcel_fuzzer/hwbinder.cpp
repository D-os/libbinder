/*
 * Copyright (C) 2019 The Android Open Source Project
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
#define FUZZ_LOG_TAG "hwbinder"

#include "hwbinder.h"
#include "util.h"

#include <android-base/logging.h>
#include <hwbinder/Parcel.h>

using ::android::status_t;

// TODO: support scatter-gather types

std::ostream& operator<<(std::ostream& os, const ::android::sp<::android::hardware::IBinder>& binder) {
    os << binder.get();
    return os;
}

#define PARCEL_READ_OPT_STATUS(T, FUN) \
    PARCEL_READ_NO_STATUS(T, FUN), PARCEL_READ_WITH_STATUS(T, FUN)

#define PARCEL_READ_NO_STATUS(T, FUN) \
    [] (const ::android::hardware::Parcel& p, uint8_t /*data*/) {\
        FUZZ_LOG() << "about to read " #T " using " #FUN " with no status";\
        T t = p.FUN();\
        FUZZ_LOG() << #T " value: " << t;\
    }

#define PARCEL_READ_WITH_STATUS(T, FUN) \
    [] (const ::android::hardware::Parcel& p, uint8_t /*data*/) {\
        FUZZ_LOG() << "about to read " #T " using " #FUN " with status";\
        T t;\
        status_t status = p.FUN(&t);\
        FUZZ_LOG() << #T " status: " << status << " value: " << t;\
    }

// clang-format off
std::vector<ParcelRead<::android::hardware::Parcel>> HWBINDER_PARCEL_READ_FUNCTIONS {
    PARCEL_READ_NO_STATUS(size_t, dataSize),
    PARCEL_READ_NO_STATUS(size_t, dataAvail),
    PARCEL_READ_NO_STATUS(size_t, dataPosition),
    PARCEL_READ_NO_STATUS(size_t, dataCapacity),
    [] (const ::android::hardware::Parcel& p, uint8_t pos) {
        FUZZ_LOG() << "about to setDataPosition: " << pos;
        p.setDataPosition(pos);
        FUZZ_LOG() << "setDataPosition done";
    },
    [] (const ::android::hardware::Parcel& p, uint8_t length) {
        FUZZ_LOG() << "about to enforceInterface";
        std::string interfaceName(length, 'a');
        bool okay = p.enforceInterface(interfaceName.c_str());
        FUZZ_LOG() << "enforceInterface status: " << okay;
    },
    PARCEL_READ_NO_STATUS(size_t, objectsCount),
    [] (const ::android::hardware::Parcel& p, uint8_t length) {
        FUZZ_LOG() << "about to read";
        std::vector<uint8_t> data (length);
        status_t status = p.read(data.data(), length);
        FUZZ_LOG() << "read status: " << status << " data: " << hexString(data.data(), data.size());
    },
    [] (const ::android::hardware::Parcel& p, uint8_t length) {
        FUZZ_LOG() << "about to read";
        std::vector<uint8_t> data (length);
        const void* inplace = p.readInplace(length);
        FUZZ_LOG() << "read status: " << hexString(inplace, length);
    },
    PARCEL_READ_WITH_STATUS(int8_t, readInt8),
    PARCEL_READ_WITH_STATUS(uint8_t, readUint8),
    PARCEL_READ_WITH_STATUS(int16_t, readInt16),
    PARCEL_READ_WITH_STATUS(uint16_t, readUint16),
    PARCEL_READ_OPT_STATUS(int32_t, readInt32),
    PARCEL_READ_OPT_STATUS(uint32_t, readUint32),
    PARCEL_READ_OPT_STATUS(int64_t, readInt64),
    PARCEL_READ_OPT_STATUS(uint64_t, readUint64),
    PARCEL_READ_OPT_STATUS(float, readFloat),
    PARCEL_READ_OPT_STATUS(double, readDouble),
    PARCEL_READ_OPT_STATUS(bool, readBool),
    [] (const ::android::hardware::Parcel& p, uint8_t /*data*/) {
        FUZZ_LOG() << "about to readCString";
        const char* str = p.readCString();
        FUZZ_LOG() << "readCString " << (str ? str : "<null>");
    },
    PARCEL_READ_OPT_STATUS(::android::String16, readString16),
    PARCEL_READ_WITH_STATUS(std::unique_ptr<::android::String16>, readString16),
    [] (const ::android::hardware::Parcel& p, uint8_t /*data*/) {
        FUZZ_LOG() << "about to readString16Inplace";
        size_t outSize = 0;
        const char16_t* str = p.readString16Inplace(&outSize);
        FUZZ_LOG() << "readString16Inplace: " << hexString(str, sizeof(char16_t) * outSize);
    },
    PARCEL_READ_OPT_STATUS(::android::sp<::android::hardware::IBinder>, readStrongBinder),
    PARCEL_READ_WITH_STATUS(::android::sp<::android::hardware::IBinder>, readNullableStrongBinder),
    [] (const ::android::hardware::Parcel& p, uint8_t size) {
        FUZZ_LOG() << "about to readBuffer";
        size_t handle = 0;
        const void* data = nullptr;
        status_t status = p.readBuffer(size, &handle, &data);
        FUZZ_LOG() << "readBuffer status: " << status << " handle: " << handle << " data: " << data;

        // should be null since we don't create any IPC objects
        CHECK(data == nullptr) << data;
    },
    [] (const ::android::hardware::Parcel& p, uint8_t size) {
        FUZZ_LOG() << "about to readNullableBuffer";
        size_t handle = 0;
        const void* data = nullptr;
        status_t status = p.readNullableBuffer(size, &handle, &data);
        FUZZ_LOG() << "readNullableBuffer status: " << status << " handle: " << handle << " data: " << data;

        // should be null since we don't create any IPC objects
        CHECK(data == nullptr) << data;
    },
    [] (const ::android::hardware::Parcel& p, uint8_t size) {
        FUZZ_LOG() << "about to readEmbeddedBuffer";
        size_t handle = 0;
        size_t parent_buffer_handle = 0;
        size_t parent_offset = 3;
        const void* data = nullptr;
        status_t status = p.readEmbeddedBuffer(size, &handle, parent_buffer_handle, parent_offset, &data);
        FUZZ_LOG() << "readEmbeddedBuffer status: " << status << " handle: " << handle << " data: " << data;

        // should be null since we don't create any IPC objects
        CHECK(data == nullptr) << data;
    },
    [] (const ::android::hardware::Parcel& p, uint8_t size) {
        FUZZ_LOG() << "about to readNullableEmbeddedBuffer";
        size_t handle = 0;
        size_t parent_buffer_handle = 0;
        size_t parent_offset = 3;
        const void* data = nullptr;
        status_t status = p.readNullableEmbeddedBuffer(size, &handle, parent_buffer_handle, parent_offset, &data);
        FUZZ_LOG() << "readNullableEmbeddedBuffer status: " << status << " handle: " << handle << " data: " << data;

        // should be null since we don't create any IPC objects
        CHECK(data == nullptr) << data;
    },
    [] (const ::android::hardware::Parcel& p, uint8_t size) {
        FUZZ_LOG() << "about to readEmbeddedNativeHandle";
        size_t parent_buffer_handle = size & 0xf;
        size_t parent_offset = size >> 4;
        const native_handle_t* handle = nullptr;
        status_t status = p.readEmbeddedNativeHandle(parent_buffer_handle, parent_offset, &handle);
        FUZZ_LOG() << "readEmbeddedNativeHandle status: " << status << " handle: " << handle << " handle: " << handle;

        // should be null since we don't create any IPC objects
        CHECK(handle == nullptr) << handle;
    },
    [] (const ::android::hardware::Parcel& p, uint8_t size) {
        FUZZ_LOG() << "about to readNullableEmbeddedNativeHandle";
        size_t parent_buffer_handle = size & 0xf;
        size_t parent_offset = size >> 4;
        const native_handle_t* handle = nullptr;
        status_t status = p.readNullableEmbeddedNativeHandle(parent_buffer_handle, parent_offset, &handle);
        FUZZ_LOG() << "readNullableEmbeddedNativeHandle status: " << status << " handle: " << handle << " handle: " << handle;

        // should be null since we don't create any IPC objects
        CHECK(handle == nullptr) << handle;
    },
    [] (const ::android::hardware::Parcel& p, uint8_t /*data*/) {
        FUZZ_LOG() << "about to readNativeHandleNoDup";
        const native_handle_t* handle = nullptr;
        status_t status = p.readNativeHandleNoDup(&handle);
        FUZZ_LOG() << "readNativeHandleNoDup status: " << status << " handle: " << handle;

        // should be null since we don't create any IPC objects
        CHECK(handle == nullptr) << handle;
        CHECK(status != ::android::OK);
    },
    [] (const ::android::hardware::Parcel& p, uint8_t /*data*/) {
        FUZZ_LOG() << "about to readNullableNativeHandleNoDup";
        const native_handle_t* handle = nullptr;
        status_t status = p.readNullableNativeHandleNoDup(&handle);
        FUZZ_LOG() << "readNullableNativeHandleNoDup status: " << status << " handle: " << handle;

        // should be null since we don't create any IPC objects
        CHECK(handle == nullptr) << handle;
    },
};
// clang-format on
