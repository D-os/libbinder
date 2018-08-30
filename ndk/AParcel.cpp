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
#include "AParcel_internal.h"

#include "AIBinder_internal.h"

#include <binder/Parcel.h>

using ::android::IBinder;
using ::android::Parcel;
using ::android::sp;

binder_status_t AParcel_writeStrongBinder(AParcel* parcel, AIBinder* binder) {
    return (*parcel)->writeStrongBinder(binder->getBinder());
}
binder_status_t AParcel_readStrongBinder(const AParcel* parcel, AIBinder** binder) {
    sp<IBinder> readBinder = nullptr;
    binder_status_t status = (*parcel)->readStrongBinder(&readBinder);
    if (status != EX_NONE) {
        return status;
    }
    *binder = new ABpBinder(readBinder);
    AIBinder_incStrong(*binder);
    return status;
}
binder_status_t AParcel_readNullableStrongBinder(const AParcel* parcel, AIBinder** binder) {
    sp<IBinder> readBinder = nullptr;
    binder_status_t status = (*parcel)->readNullableStrongBinder(&readBinder);
    if (status != EX_NONE) {
        return status;
    }
    *binder = new ABpBinder(readBinder);
    AIBinder_incStrong(*binder);
    return status;
}

// See gen_parcel_helper.py. These auto-generated read/write methods use the same types for
// libbinder and this library.
// @START
binder_status_t AParcel_writeInt32(AParcel* parcel, int32_t value) {
    return (*parcel)->writeInt32(value);
}

binder_status_t AParcel_writeUint32(AParcel* parcel, uint32_t value) {
    return (*parcel)->writeUint32(value);
}

binder_status_t AParcel_writeInt64(AParcel* parcel, int64_t value) {
    return (*parcel)->writeInt64(value);
}

binder_status_t AParcel_writeUint64(AParcel* parcel, uint64_t value) {
    return (*parcel)->writeUint64(value);
}

binder_status_t AParcel_writeFloat(AParcel* parcel, float value) {
    return (*parcel)->writeFloat(value);
}

binder_status_t AParcel_writeDouble(AParcel* parcel, double value) {
    return (*parcel)->writeDouble(value);
}

binder_status_t AParcel_writeBool(AParcel* parcel, bool value) {
    return (*parcel)->writeBool(value);
}

binder_status_t AParcel_writeChar(AParcel* parcel, char16_t value) {
    return (*parcel)->writeChar(value);
}

binder_status_t AParcel_writeByte(AParcel* parcel, int8_t value) {
    return (*parcel)->writeByte(value);
}

binder_status_t AParcel_readInt32(const AParcel* parcel, int32_t* value) {
    return (*parcel)->readInt32(value);
}

binder_status_t AParcel_readUint32(const AParcel* parcel, uint32_t* value) {
    return (*parcel)->readUint32(value);
}

binder_status_t AParcel_readInt64(const AParcel* parcel, int64_t* value) {
    return (*parcel)->readInt64(value);
}

binder_status_t AParcel_readUint64(const AParcel* parcel, uint64_t* value) {
    return (*parcel)->readUint64(value);
}

binder_status_t AParcel_readFloat(const AParcel* parcel, float* value) {
    return (*parcel)->readFloat(value);
}

binder_status_t AParcel_readDouble(const AParcel* parcel, double* value) {
    return (*parcel)->readDouble(value);
}

binder_status_t AParcel_readBool(const AParcel* parcel, bool* value) {
    return (*parcel)->readBool(value);
}

binder_status_t AParcel_readChar(const AParcel* parcel, char16_t* value) {
    return (*parcel)->readChar(value);
}

binder_status_t AParcel_readByte(const AParcel* parcel, int8_t* value) {
    return (*parcel)->readByte(value);
}

// @END
