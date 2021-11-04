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
#define FUZZ_LOG_TAG "binder_ndk"

#include "binder_ndk.h"

#include <android/binder_parcel_utils.h>
#include <android/binder_parcelable_utils.h>

#include "util.h"

// TODO(b/142061461): parent class
class SomeParcelable {
public:
    binder_status_t writeToParcel(AParcel* /*parcel*/) { return STATUS_OK; }
    binder_status_t readFromParcel(const AParcel* parcel) {
        return AParcel_readInt32(parcel, &mValue);
    }

private:
    int32_t mValue = 0;
};

class ISomeInterface : public ::ndk::ICInterface {
public:
    ISomeInterface() = default;
    virtual ~ISomeInterface() = default;
    static binder_status_t readFromParcel(const AParcel* parcel,
                                          std::shared_ptr<ISomeInterface>* instance);
};

static binder_status_t onTransact(AIBinder*, transaction_code_t, const AParcel*, AParcel*) {
    return STATUS_UNKNOWN_TRANSACTION;
}

static AIBinder_Class* g_class = ::ndk::ICInterface::defineClass("ISomeInterface", onTransact);

class BpSomeInterface : public ::ndk::BpCInterface<ISomeInterface> {
public:
    explicit BpSomeInterface(const ::ndk::SpAIBinder& binder) : BpCInterface(binder) {}
    virtual ~BpSomeInterface() = default;
};

binder_status_t ISomeInterface::readFromParcel(const AParcel* parcel,
                                               std::shared_ptr<ISomeInterface>* instance) {
    ::ndk::SpAIBinder binder;
    binder_status_t status = AParcel_readStrongBinder(parcel, binder.getR());
    if (status == STATUS_OK) {
        if (AIBinder_associateClass(binder.get(), g_class)) {
            *instance = std::static_pointer_cast<ISomeInterface>(
                    ::ndk::ICInterface::asInterface(binder.get()));
        } else {
            *instance = ::ndk::SharedRefBase::make<BpSomeInterface>(binder);
        }
    }
    return status;
}

#define PARCEL_READ(T, FUN)                                              \
    [](const NdkParcelAdapter& p, uint8_t /*data*/) {                    \
        FUZZ_LOG() << "about to read " #T " using " #FUN " with status"; \
        T t{};                                                           \
        binder_status_t status = FUN(p.aParcel(), &t);                   \
        FUZZ_LOG() << #T " status: " << status /* << " value: " << t*/;  \
    }

// clang-format off
std::vector<ParcelRead<NdkParcelAdapter>> BINDER_NDK_PARCEL_READ_FUNCTIONS{
        // methods from binder_parcel.h
        [](const NdkParcelAdapter& p, uint8_t pos) {
            FUZZ_LOG() << "about to set data position to " << pos;
            binder_status_t status = AParcel_setDataPosition(p.aParcel(), pos);
            FUZZ_LOG() << "set data position: " << status;
        },
        [](const NdkParcelAdapter& p, uint8_t /*data*/) {
            FUZZ_LOG() << "about to read status header";
            ndk::ScopedAStatus t;
            binder_status_t status = AParcel_readStatusHeader(p.aParcel(), t.getR());
            FUZZ_LOG() << "read status header: " << status;
        },
        [](const NdkParcelAdapter& p, uint8_t /*data*/) {
            FUZZ_LOG() << "about to getDataSize the parcel";
            AParcel_getDataSize(p.aParcel());
            FUZZ_LOG() << "getDataSize done";
        },
        [](const NdkParcelAdapter& p, uint8_t data) {
            FUZZ_LOG() << "about to read a ParcelableHolder";
            ndk::AParcelableHolder ph {(data % 2 == 1) ? ndk::STABILITY_LOCAL : ndk::STABILITY_VINTF};
            binder_status_t status = AParcel_readParcelable(p.aParcel(), &ph);
            FUZZ_LOG() << "read the ParcelableHolder: " << status;
        },
        [](const NdkParcelAdapter& p, uint8_t data) {
            FUZZ_LOG() << "about to appendFrom";
            AParcel* parcel = AParcel_create();
            binder_status_t status = AParcel_appendFrom(p.aParcel(), parcel, 0, data);
            AParcel_delete(parcel);
            FUZZ_LOG() << "appendFrom: " << status;
        },

        PARCEL_READ(int32_t, AParcel_readInt32),
        PARCEL_READ(uint32_t, AParcel_readUint32),
        PARCEL_READ(int64_t, AParcel_readInt64),
        PARCEL_READ(uint64_t, AParcel_readUint64),
        PARCEL_READ(float, AParcel_readFloat),
        PARCEL_READ(double, AParcel_readDouble),
        PARCEL_READ(bool, AParcel_readBool),
        PARCEL_READ(char16_t, AParcel_readChar),
        PARCEL_READ(int8_t, AParcel_readByte),

        // methods from binder_parcel_utils.h
        PARCEL_READ(ndk::SpAIBinder, ndk::AParcel_readNullableStrongBinder),
        PARCEL_READ(ndk::SpAIBinder, ndk::AParcel_readRequiredStrongBinder),
        PARCEL_READ(ndk::ScopedFileDescriptor, ndk::AParcel_readNullableParcelFileDescriptor),
        PARCEL_READ(ndk::ScopedFileDescriptor, ndk::AParcel_readRequiredParcelFileDescriptor),
        PARCEL_READ(std::string, ndk::AParcel_readString),
        PARCEL_READ(std::optional<std::string>, ndk::AParcel_readString),

        PARCEL_READ(std::vector<std::string>, ndk::AParcel_readVector),
        PARCEL_READ(std::optional<std::vector<std::optional<std::string>>>, ndk::AParcel_readVector),
        PARCEL_READ(std::vector<SomeParcelable>, ndk::AParcel_readVector),
        PARCEL_READ(std::optional<std::vector<std::optional<SomeParcelable>>>, ndk::AParcel_readVector),
        PARCEL_READ(std::vector<ndk::SpAIBinder>, ndk::AParcel_readVector),
        PARCEL_READ(std::optional<std::vector<ndk::SpAIBinder>>, ndk::AParcel_readVector),
        PARCEL_READ(std::vector<ndk::ScopedFileDescriptor>, ndk::AParcel_readVector),
        PARCEL_READ(std::optional<std::vector<ndk::ScopedFileDescriptor>>, ndk::AParcel_readVector),
        PARCEL_READ(std::vector<std::shared_ptr<ISomeInterface>>, ndk::AParcel_readVector),
        PARCEL_READ(std::optional<std::vector<std::shared_ptr<ISomeInterface>>>, ndk::AParcel_readVector),
        PARCEL_READ(std::vector<int32_t>, ndk::AParcel_readVector),
        PARCEL_READ(std::optional<std::vector<int32_t>>, ndk::AParcel_readVector),
        PARCEL_READ(std::vector<uint32_t>, ndk::AParcel_readVector),
        PARCEL_READ(std::optional<std::vector<uint32_t>>, ndk::AParcel_readVector),
        PARCEL_READ(std::vector<int64_t>, ndk::AParcel_readVector),
        PARCEL_READ(std::optional<std::vector<int64_t>>, ndk::AParcel_readVector),
        PARCEL_READ(std::vector<uint64_t>, ndk::AParcel_readVector),
        PARCEL_READ(std::optional<std::vector<uint64_t>>, ndk::AParcel_readVector),
        PARCEL_READ(std::vector<float>, ndk::AParcel_readVector),
        PARCEL_READ(std::optional<std::vector<float>>, ndk::AParcel_readVector),
        PARCEL_READ(std::vector<double>, ndk::AParcel_readVector),
        PARCEL_READ(std::optional<std::vector<double>>, ndk::AParcel_readVector),
        PARCEL_READ(std::vector<bool>, ndk::AParcel_readVector),
        PARCEL_READ(std::optional<std::vector<bool>>, ndk::AParcel_readVector),
        PARCEL_READ(std::vector<char16_t>, ndk::AParcel_readVector),
        PARCEL_READ(std::optional<std::vector<char16_t>>, ndk::AParcel_readVector),
        PARCEL_READ(std::vector<int32_t>, ndk::AParcel_resizeVector),
        PARCEL_READ(std::optional<std::vector<int32_t>>, ndk::AParcel_resizeVector),
};
// clang-format on
