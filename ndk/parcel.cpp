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

#include <android/binder_parcel.h>
#include "parcel_internal.h"

#include "ibinder_internal.h"
#include "status_internal.h"

#include <limits>

#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <binder/Parcel.h>
#include <binder/ParcelFileDescriptor.h>
#include <utils/Unicode.h>

using ::android::IBinder;
using ::android::Parcel;
using ::android::sp;
using ::android::status_t;
using ::android::base::unique_fd;
using ::android::os::ParcelFileDescriptor;

template <typename T>
using ContiguousArrayGetter = T* (*)(void* arrayData);
template <typename T>
using ArrayGetter = T (*)(const void* arrayData, size_t index);
template <typename T>
using ArraySetter = void (*)(void* arrayData, size_t index, T value);

template <typename T>
binder_status_t WriteArray(AParcel* parcel, const T* array, size_t length) {
    if (length > std::numeric_limits<int32_t>::max()) return STATUS_BAD_VALUE;

    Parcel* rawParcel = parcel->get();

    status_t status = rawParcel->writeInt32(static_cast<int32_t>(length));
    if (status != STATUS_OK) return PruneStatusT(status);

    int32_t size = 0;
    if (__builtin_smul_overflow(sizeof(T), length, &size)) return STATUS_NO_MEMORY;

    void* const data = rawParcel->writeInplace(size);
    if (data == nullptr) return STATUS_NO_MEMORY;

    memcpy(data, array, size);

    return STATUS_OK;
}

// Each element in a char16_t array is converted to an int32_t (not packed).
template <>
binder_status_t WriteArray<char16_t>(AParcel* parcel, const char16_t* array, size_t length) {
    if (length > std::numeric_limits<int32_t>::max()) return STATUS_BAD_VALUE;

    Parcel* rawParcel = parcel->get();

    status_t status = rawParcel->writeInt32(static_cast<int32_t>(length));
    if (status != STATUS_OK) return PruneStatusT(status);

    int32_t size = 0;
    if (__builtin_smul_overflow(sizeof(char16_t), length, &size)) return STATUS_NO_MEMORY;

    for (int32_t i = 0; i < length; i++) {
        status = rawParcel->writeChar(array[i]);

        if (status != STATUS_OK) return PruneStatusT(status);
    }

    return STATUS_OK;
}

template <typename T>
binder_status_t ReadArray(const AParcel* parcel, void** arrayData,
                          AParcel_arrayReallocator reallocator, ContiguousArrayGetter<T> getter) {
    const Parcel* rawParcel = parcel->get();

    int32_t length;
    status_t status = rawParcel->readInt32(&length);

    if (status != STATUS_OK) return PruneStatusT(status);
    if (length < 0) return STATUS_UNEXPECTED_NULL;

    *arrayData = reallocator(*arrayData, length);
    if (*arrayData == nullptr) return STATUS_NO_MEMORY;

    if (length == 0) return STATUS_OK;

    T* array = getter(*arrayData);
    if (array == nullptr) return STATUS_NO_MEMORY;

    int32_t size = 0;
    if (__builtin_smul_overflow(sizeof(T), length, &size)) return STATUS_NO_MEMORY;

    const void* data = rawParcel->readInplace(size);
    if (data == nullptr) return STATUS_NO_MEMORY;

    memcpy(array, data, size);

    return STATUS_OK;
}

// Each element in a char16_t array is converted to an int32_t (not packed)
template <>
binder_status_t ReadArray<char16_t>(const AParcel* parcel, void** arrayData,
                                    AParcel_arrayReallocator reallocator,
                                    ContiguousArrayGetter<char16_t> getter) {
    const Parcel* rawParcel = parcel->get();

    int32_t length;
    status_t status = rawParcel->readInt32(&length);

    if (status != STATUS_OK) return PruneStatusT(status);
    if (length < 0) return STATUS_UNEXPECTED_NULL;

    *arrayData = reallocator(*arrayData, length);
    if (*arrayData == nullptr) return STATUS_NO_MEMORY;

    if (length == 0) return STATUS_OK;

    char16_t* array = getter(*arrayData);
    if (array == nullptr) return STATUS_NO_MEMORY;

    int32_t size = 0;
    if (__builtin_smul_overflow(sizeof(char16_t), length, &size)) return STATUS_NO_MEMORY;

    for (int32_t i = 0; i < length; i++) {
        status = rawParcel->readChar(array + i);

        if (status != STATUS_OK) return PruneStatusT(status);
    }

    return STATUS_OK;
}

template <typename T>
binder_status_t WriteArray(AParcel* parcel, const void* arrayData, ArrayGetter<T> getter,
                           size_t length, status_t (Parcel::*write)(T)) {
    if (length > std::numeric_limits<int32_t>::max()) return STATUS_BAD_VALUE;

    Parcel* rawParcel = parcel->get();

    status_t status = rawParcel->writeInt32(static_cast<int32_t>(length));
    if (status != STATUS_OK) return PruneStatusT(status);

    for (size_t i = 0; i < length; i++) {
        status = (rawParcel->*write)(getter(arrayData, i));

        if (status != STATUS_OK) return PruneStatusT(status);
    }

    return STATUS_OK;
}

template <typename T>
binder_status_t ReadArray(const AParcel* parcel, void** arrayData,
                          AParcel_arrayReallocator reallocator, ArraySetter<T> setter,
                          status_t (Parcel::*read)(T*) const) {
    const Parcel* rawParcel = parcel->get();

    int32_t length;
    status_t status = rawParcel->readInt32(&length);

    if (status != STATUS_OK) return PruneStatusT(status);
    if (length < 0) return STATUS_UNEXPECTED_NULL;

    *arrayData = reallocator(*arrayData, length);
    if (*arrayData == nullptr) return STATUS_NO_MEMORY;

    for (size_t i = 0; i < length; i++) {
        T readTarget;
        status = (rawParcel->*read)(&readTarget);
        if (status != STATUS_OK) return PruneStatusT(status);

        setter(*arrayData, i, readTarget);
    }

    return STATUS_OK;
}

void AParcel_delete(AParcel* parcel) {
    delete parcel;
}

binder_status_t AParcel_writeStrongBinder(AParcel* parcel, AIBinder* binder) {
    sp<IBinder> writeBinder = binder != nullptr ? binder->getBinder() : nullptr;
    return parcel->get()->writeStrongBinder(writeBinder);
}
binder_status_t AParcel_readStrongBinder(const AParcel* parcel, AIBinder** binder) {
    sp<IBinder> readBinder = nullptr;
    status_t status = parcel->get()->readStrongBinder(&readBinder);
    if (status != STATUS_OK) {
        return PruneStatusT(status);
    }
    sp<AIBinder> ret = ABpBinder::lookupOrCreateFromBinder(readBinder);
    AIBinder_incStrong(ret.get());
    *binder = ret.get();
    return PruneStatusT(status);
}
binder_status_t AParcel_readNullableStrongBinder(const AParcel* parcel, AIBinder** binder) {
    sp<IBinder> readBinder = nullptr;
    status_t status = parcel->get()->readNullableStrongBinder(&readBinder);
    if (status != STATUS_OK) {
        return PruneStatusT(status);
    }
    sp<AIBinder> ret = ABpBinder::lookupOrCreateFromBinder(readBinder);
    AIBinder_incStrong(ret.get());
    *binder = ret.get();
    return PruneStatusT(status);
}

binder_status_t AParcel_writeParcelFileDescriptor(AParcel* parcel, int fd) {
    ParcelFileDescriptor parcelFd((unique_fd(fd)));

    status_t status = parcel->get()->writeParcelable(parcelFd);

    // ownership is retained by caller
    (void)parcelFd.release().release();

    return PruneStatusT(status);
}

binder_status_t AParcel_readParcelFileDescriptor(const AParcel* parcel, int* fd) {
    ParcelFileDescriptor parcelFd;
    // status_t status = parcelFd.readFromParcel(parcel->get());
    status_t status = parcel->get()->readParcelable(&parcelFd);
    if (status != STATUS_OK) return PruneStatusT(status);

    *fd = parcelFd.release().release();
    return STATUS_OK;
}

binder_status_t AParcel_writeStatusHeader(AParcel* parcel, const AStatus* status) {
    return PruneStatusT(status->get()->writeToParcel(parcel->get()));
}
binder_status_t AParcel_readStatusHeader(const AParcel* parcel, AStatus** status) {
    ::android::binder::Status bstatus;
    binder_status_t ret = PruneStatusT(bstatus.readFromParcel(*parcel->get()));
    if (ret == EX_NONE) {
        *status = new AStatus(std::move(bstatus));
    }
    return ret;
}

binder_status_t AParcel_writeString(AParcel* parcel, const char* string, size_t length) {
    const uint8_t* str8 = (uint8_t*)string;

    const ssize_t len16 = utf8_to_utf16_length(str8, length);

    if (len16 < 0 || len16 >= std::numeric_limits<int32_t>::max()) {
        LOG(WARNING) << __func__ << ": Invalid string length: " << len16;
        return STATUS_BAD_VALUE;
    }

    status_t err = parcel->get()->writeInt32(len16);
    if (err) {
        return PruneStatusT(err);
    }

    void* str16 = parcel->get()->writeInplace((len16 + 1) * sizeof(char16_t));
    if (str16 == nullptr) {
        return STATUS_NO_MEMORY;
    }

    utf8_to_utf16(str8, length, (char16_t*)str16, (size_t)len16 + 1);

    return STATUS_OK;
}

binder_status_t AParcel_readString(const AParcel* parcel, AParcel_stringReallocator reallocator,
                                   AParcel_stringGetter getter, void** stringData) {
    size_t len16;
    const char16_t* str16 = parcel->get()->readString16Inplace(&len16);

    if (str16 == nullptr) {
        LOG(WARNING) << __func__ << ": Failed to read string in place.";
        return STATUS_UNEXPECTED_NULL;
    }

    ssize_t len8;

    if (len16 == 0) {
        len8 = 1;
    } else {
        len8 = utf16_to_utf8_length(str16, len16) + 1;
    }

    if (len8 <= 0 || len8 >= std::numeric_limits<int32_t>::max()) {
        LOG(WARNING) << __func__ << ": Invalid string length: " << len8;
        return STATUS_BAD_VALUE;
    }

    *stringData = reallocator(*stringData, len8);

    if (*stringData == nullptr) {
        return STATUS_NO_MEMORY;
    }

    char* str8 = getter(*stringData);

    if (str8 == nullptr) {
        LOG(WARNING) << __func__ << ": AParcel_stringReallocator failed to allocate.";
        return STATUS_NO_MEMORY;
    }

    utf16_to_utf8(str16, len16, str8, len8);

    return STATUS_OK;
}

// See gen_parcel_helper.py. These auto-generated read/write methods use the same types for
// libbinder and this library.
// @START
binder_status_t AParcel_writeInt32(AParcel* parcel, int32_t value) {
    status_t status = parcel->get()->writeInt32(value);
    return PruneStatusT(status);
}

binder_status_t AParcel_writeUint32(AParcel* parcel, uint32_t value) {
    status_t status = parcel->get()->writeUint32(value);
    return PruneStatusT(status);
}

binder_status_t AParcel_writeInt64(AParcel* parcel, int64_t value) {
    status_t status = parcel->get()->writeInt64(value);
    return PruneStatusT(status);
}

binder_status_t AParcel_writeUint64(AParcel* parcel, uint64_t value) {
    status_t status = parcel->get()->writeUint64(value);
    return PruneStatusT(status);
}

binder_status_t AParcel_writeFloat(AParcel* parcel, float value) {
    status_t status = parcel->get()->writeFloat(value);
    return PruneStatusT(status);
}

binder_status_t AParcel_writeDouble(AParcel* parcel, double value) {
    status_t status = parcel->get()->writeDouble(value);
    return PruneStatusT(status);
}

binder_status_t AParcel_writeBool(AParcel* parcel, bool value) {
    status_t status = parcel->get()->writeBool(value);
    return PruneStatusT(status);
}

binder_status_t AParcel_writeChar(AParcel* parcel, char16_t value) {
    status_t status = parcel->get()->writeChar(value);
    return PruneStatusT(status);
}

binder_status_t AParcel_writeByte(AParcel* parcel, int8_t value) {
    status_t status = parcel->get()->writeByte(value);
    return PruneStatusT(status);
}

binder_status_t AParcel_readInt32(const AParcel* parcel, int32_t* value) {
    status_t status = parcel->get()->readInt32(value);
    return PruneStatusT(status);
}

binder_status_t AParcel_readUint32(const AParcel* parcel, uint32_t* value) {
    status_t status = parcel->get()->readUint32(value);
    return PruneStatusT(status);
}

binder_status_t AParcel_readInt64(const AParcel* parcel, int64_t* value) {
    status_t status = parcel->get()->readInt64(value);
    return PruneStatusT(status);
}

binder_status_t AParcel_readUint64(const AParcel* parcel, uint64_t* value) {
    status_t status = parcel->get()->readUint64(value);
    return PruneStatusT(status);
}

binder_status_t AParcel_readFloat(const AParcel* parcel, float* value) {
    status_t status = parcel->get()->readFloat(value);
    return PruneStatusT(status);
}

binder_status_t AParcel_readDouble(const AParcel* parcel, double* value) {
    status_t status = parcel->get()->readDouble(value);
    return PruneStatusT(status);
}

binder_status_t AParcel_readBool(const AParcel* parcel, bool* value) {
    status_t status = parcel->get()->readBool(value);
    return PruneStatusT(status);
}

binder_status_t AParcel_readChar(const AParcel* parcel, char16_t* value) {
    status_t status = parcel->get()->readChar(value);
    return PruneStatusT(status);
}

binder_status_t AParcel_readByte(const AParcel* parcel, int8_t* value) {
    status_t status = parcel->get()->readByte(value);
    return PruneStatusT(status);
}

binder_status_t AParcel_writeInt32Array(AParcel* parcel, const int32_t* value, size_t length) {
    return WriteArray<int32_t>(parcel, value, length);
}

binder_status_t AParcel_writeUint32Array(AParcel* parcel, const uint32_t* value, size_t length) {
    return WriteArray<uint32_t>(parcel, value, length);
}

binder_status_t AParcel_writeInt64Array(AParcel* parcel, const int64_t* value, size_t length) {
    return WriteArray<int64_t>(parcel, value, length);
}

binder_status_t AParcel_writeUint64Array(AParcel* parcel, const uint64_t* value, size_t length) {
    return WriteArray<uint64_t>(parcel, value, length);
}

binder_status_t AParcel_writeFloatArray(AParcel* parcel, const float* value, size_t length) {
    return WriteArray<float>(parcel, value, length);
}

binder_status_t AParcel_writeDoubleArray(AParcel* parcel, const double* value, size_t length) {
    return WriteArray<double>(parcel, value, length);
}

binder_status_t AParcel_writeBoolArray(AParcel* parcel, const void* arrayData,
                                       AParcel_boolArrayGetter getter, size_t length) {
    return WriteArray<bool>(parcel, arrayData, getter, length, &Parcel::writeBool);
}

binder_status_t AParcel_writeCharArray(AParcel* parcel, const char16_t* value, size_t length) {
    return WriteArray<char16_t>(parcel, value, length);
}

binder_status_t AParcel_writeByteArray(AParcel* parcel, const int8_t* value, size_t length) {
    return WriteArray<int8_t>(parcel, value, length);
}

binder_status_t AParcel_readInt32Array(const AParcel* parcel, void** arrayData,
                                       AParcel_arrayReallocator reallocator,
                                       AParcel_int32ArrayGetter getter) {
    return ReadArray<int32_t>(parcel, arrayData, reallocator, getter);
}

binder_status_t AParcel_readUint32Array(const AParcel* parcel, void** arrayData,
                                        AParcel_arrayReallocator reallocator,
                                        AParcel_uint32ArrayGetter getter) {
    return ReadArray<uint32_t>(parcel, arrayData, reallocator, getter);
}

binder_status_t AParcel_readInt64Array(const AParcel* parcel, void** arrayData,
                                       AParcel_arrayReallocator reallocator,
                                       AParcel_int64ArrayGetter getter) {
    return ReadArray<int64_t>(parcel, arrayData, reallocator, getter);
}

binder_status_t AParcel_readUint64Array(const AParcel* parcel, void** arrayData,
                                        AParcel_arrayReallocator reallocator,
                                        AParcel_uint64ArrayGetter getter) {
    return ReadArray<uint64_t>(parcel, arrayData, reallocator, getter);
}

binder_status_t AParcel_readFloatArray(const AParcel* parcel, void** arrayData,
                                       AParcel_arrayReallocator reallocator,
                                       AParcel_floatArrayGetter getter) {
    return ReadArray<float>(parcel, arrayData, reallocator, getter);
}

binder_status_t AParcel_readDoubleArray(const AParcel* parcel, void** arrayData,
                                        AParcel_arrayReallocator reallocator,
                                        AParcel_doubleArrayGetter getter) {
    return ReadArray<double>(parcel, arrayData, reallocator, getter);
}

binder_status_t AParcel_readBoolArray(const AParcel* parcel, void** arrayData,
                                      AParcel_arrayReallocator reallocator,
                                      AParcel_boolArraySetter setter) {
    return ReadArray<bool>(parcel, arrayData, reallocator, setter, &Parcel::readBool);
}

binder_status_t AParcel_readCharArray(const AParcel* parcel, void** arrayData,
                                      AParcel_arrayReallocator reallocator,
                                      AParcel_charArrayGetter getter) {
    return ReadArray<char16_t>(parcel, arrayData, reallocator, getter);
}

binder_status_t AParcel_readByteArray(const AParcel* parcel, void** arrayData,
                                      AParcel_arrayReallocator reallocator,
                                      AParcel_byteArrayGetter getter) {
    return ReadArray<int8_t>(parcel, arrayData, reallocator, getter);
}

// @END
