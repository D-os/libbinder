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

#include <binder/Parcel.h>

using ::android::IBinder;
using ::android::Parcel;
using ::android::sp;
using ::android::status_t;

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

// @END
