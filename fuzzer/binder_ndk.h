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

#include <android/binder_auto_utils.h>
#include <vector>

#include <android/binder_parcel.h>
#include "parcel_fuzzer.h"

// libbinder_ndk doesn't export this header which breaks down its API for NDK
// and APEX users, but we need access to it to fuzz.
#include "../ndk/parcel_internal.h"

class NdkParcelAdapter {
public:
    NdkParcelAdapter() : mParcel(new AParcel(nullptr /*binder*/)) {}

    const AParcel* aParcel() const { return mParcel.get(); }
    AParcel* aParcel() { return mParcel.get(); }

    size_t dataSize() const { return aParcel()->get()->dataSize(); }
    size_t dataAvail() const { return aParcel()->get()->dataAvail(); }
    size_t dataPosition() const { return aParcel()->get()->dataPosition(); }
    size_t dataCapacity() const { return aParcel()->get()->dataCapacity(); }
    android::status_t setData(const uint8_t* buffer, size_t len) {
        return aParcel()->get()->setData(buffer, len);
    }

private:
    ndk::ScopedAParcel mParcel;
};

extern std::vector<ParcelRead<NdkParcelAdapter>> BINDER_NDK_PARCEL_READ_FUNCTIONS;
