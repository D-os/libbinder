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
#define FUZZ_LOG_TAG "binder"

#include "binder.h"
#include "util.h"

#include <android/os/IServiceManager.h>
#include <binder/ParcelableHolder.h>
#include <binder/PersistableBundle.h>

using ::android::status_t;

enum ByteEnum : int8_t {};
enum IntEnum : int32_t {};
enum LongEnum : int64_t {};

class ExampleParcelable : public android::Parcelable {
public:
    status_t writeToParcel(android::Parcel* /*parcel*/) const override {
        FUZZ_LOG() << "should not reach";
        abort();
    }
    status_t readFromParcel(const android::Parcel* parcel) override {
        mExampleExtraField++;
        return parcel->readInt64(&(this->mExampleUsedData));
    }
private:
    int64_t mExampleExtraField = 0;
    int64_t mExampleUsedData = 0;
};

struct ExampleFlattenable : public android::Flattenable<ExampleFlattenable> {
public:
    size_t getFlattenedSize() const { return sizeof(mValue); }
    size_t getFdCount() const { return 0; }
    status_t flatten(void*& /*buffer*/, size_t& /*size*/, int*& /*fds*/, size_t& /*count*/) const {
        FUZZ_LOG() << "should not reach";
        abort();
    }
    status_t unflatten(void const*& buffer, size_t& size, int const*& /*fds*/, size_t& /*count*/) {
        if (size < sizeof(mValue)) {
            return android::NO_MEMORY;
        }
        android::FlattenableUtils::read(buffer, size, mValue);
        return android::OK;
    }
private:
    int32_t mValue = 0xFEEDBEEF;
};

struct ExampleLightFlattenable : public android::LightFlattenablePod<ExampleLightFlattenable> {
    int32_t mValue = 0;
};

#define PARCEL_READ_WITH_STATUS(T, FUN) \
    [] (const ::android::Parcel& p, uint8_t /*data*/) {\
        FUZZ_LOG() << "about to read " #T " using " #FUN " with status";\
        T t{};\
        status_t status = p.FUN(&t);\
        FUZZ_LOG() << #T " status: " << status /* << " value: " << t*/;\
    }

#define PARCEL_READ_NO_STATUS(T, FUN) \
    [] (const ::android::Parcel& p, uint8_t /*data*/) {\
        FUZZ_LOG() << "about to read " #T " using " #FUN " with no status";\
        T t = p.FUN();\
        (void) t;\
        FUZZ_LOG() << #T " done " /* << " value: " << t*/;\
    }

#define PARCEL_READ_OPT_STATUS(T, FUN) \
    PARCEL_READ_WITH_STATUS(T, FUN), \
    PARCEL_READ_NO_STATUS(T, FUN)

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
// clang-format off
std::vector<ParcelRead<::android::Parcel>> BINDER_PARCEL_READ_FUNCTIONS {
    PARCEL_READ_NO_STATUS(size_t, dataSize),
    PARCEL_READ_NO_STATUS(size_t, dataAvail),
    PARCEL_READ_NO_STATUS(size_t, dataPosition),
    PARCEL_READ_NO_STATUS(size_t, dataCapacity),
    [] (const ::android::Parcel& p, uint8_t pos) {
        FUZZ_LOG() << "about to setDataPosition: " << pos;
        p.setDataPosition(pos);
        FUZZ_LOG() << "setDataPosition done";
    },
    PARCEL_READ_NO_STATUS(size_t, allowFds),
    PARCEL_READ_NO_STATUS(size_t, hasFileDescriptors),
    [] (const ::android::Parcel& p, uint8_t len) {
        std::string interface(len, 'a');
        FUZZ_LOG() << "about to enforceInterface: " << interface;
        bool b = p.enforceInterface(::android::String16(interface.c_str()));
        FUZZ_LOG() << "enforced interface: " << b;
    },
    [] (const ::android::Parcel& p, uint8_t /*len*/) {
        FUZZ_LOG() << "about to checkInterface";
        android::sp<android::IBinder> aBinder = new android::BBinder();
        bool b = p.checkInterface(aBinder.get());
        FUZZ_LOG() << "checked interface: " << b;
    },
    PARCEL_READ_NO_STATUS(size_t, objectsCount),
    PARCEL_READ_NO_STATUS(status_t, errorCheck),
    [] (const ::android::Parcel& p, uint8_t len) {
        FUZZ_LOG() << "about to read void*";
        std::vector<uint8_t> data(len);
        status_t status = p.read(data.data(), len);
        FUZZ_LOG() << "read status: " << status;
    },
    [] (const ::android::Parcel& p, uint8_t len) {
        FUZZ_LOG() << "about to readInplace";
        const void* r = p.readInplace(len);
        FUZZ_LOG() << "readInplace done. pointer: " << r << " bytes: " << hexString(r, len);
    },
    PARCEL_READ_OPT_STATUS(int32_t, readInt32),
    PARCEL_READ_OPT_STATUS(uint32_t, readUint32),
    PARCEL_READ_OPT_STATUS(int64_t, readInt64),
    PARCEL_READ_OPT_STATUS(uint64_t, readUint64),
    PARCEL_READ_OPT_STATUS(float, readFloat),
    PARCEL_READ_OPT_STATUS(double, readDouble),
    PARCEL_READ_OPT_STATUS(bool, readBool),
    PARCEL_READ_OPT_STATUS(char16_t, readChar),
    PARCEL_READ_OPT_STATUS(int8_t, readByte),

    PARCEL_READ_WITH_STATUS(std::string, readUtf8FromUtf16),
    PARCEL_READ_WITH_STATUS(std::unique_ptr<std::string>, readUtf8FromUtf16),
    PARCEL_READ_WITH_STATUS(std::optional<std::string>, readUtf8FromUtf16),
    [] (const ::android::Parcel& p, uint8_t /*data*/) {
        FUZZ_LOG() << "about to read c-str";
        const char* str = p.readCString();
        FUZZ_LOG() << "read c-str: " << (str ? str : "<empty string>");
    },
    PARCEL_READ_OPT_STATUS(android::String8, readString8),
    PARCEL_READ_OPT_STATUS(android::String16, readString16),
    PARCEL_READ_WITH_STATUS(std::unique_ptr<android::String16>, readString16),
    PARCEL_READ_WITH_STATUS(std::optional<android::String16>, readString16),
    [] (const ::android::Parcel& p, uint8_t /*data*/) {
        FUZZ_LOG() << "about to readString16Inplace";
        size_t outLen = 0;
        const char16_t* str = p.readString16Inplace(&outLen);
        FUZZ_LOG() << "readString16Inplace: " << hexString(str, sizeof(char16_t) * outLen)
                   << " size: " << outLen;
    },
    PARCEL_READ_WITH_STATUS(android::sp<android::IBinder>, readStrongBinder),
    PARCEL_READ_WITH_STATUS(android::sp<android::IBinder>, readNullableStrongBinder),

    // TODO(b/131868573): can force read of arbitrarily sized vector
    // PARCEL_READ_WITH_STATUS(std::vector<ByteEnum>, readEnumVector),
    // PARCEL_READ_WITH_STATUS(std::unique_ptr<std::vector<ByteEnum>>, readEnumVector),
    // PARCEL_READ_WITH_STATUS(std::optional<std::vector<ByteEnum>>, readEnumVector),
    // PARCEL_READ_WITH_STATUS(std::vector<IntEnum>, readEnumVector),
    // PARCEL_READ_WITH_STATUS(std::unique_ptr<std::vector<IntEnum>>, readEnumVector),
    // PARCEL_READ_WITH_STATUS(std::optional<std::vector<IntEnum>>, readEnumVector),
    // PARCEL_READ_WITH_STATUS(std::vector<LongEnum>, readEnumVector),
    // PARCEL_READ_WITH_STATUS(std::unique_ptr<std::vector<LongEnum>>, readEnumVector),
    // PARCEL_READ_WITH_STATUS(std::optional<std::vector<LongEnum>>, readEnumVector),

    // only reading one parcelable type for now
    // TODO(b/131868573): can force read of arbitrarily sized vector
    // PARCEL_READ_WITH_STATUS(std::unique_ptr<std::vector<std::unique_ptr<ExampleParcelable>>>, readParcelableVector),
    // PARCEL_READ_WITH_STATUS(std::optional<std::vector<std::optional<ExampleParcelable>>>, readParcelableVector),
    // PARCEL_READ_WITH_STATUS(std::vector<ExampleParcelable>, readParcelableVector),
    PARCEL_READ_WITH_STATUS(ExampleParcelable, readParcelable),
    PARCEL_READ_WITH_STATUS(std::unique_ptr<ExampleParcelable>, readParcelable),
    PARCEL_READ_WITH_STATUS(std::optional<ExampleParcelable>, readParcelable),

    // only reading one binder type for now
    PARCEL_READ_WITH_STATUS(android::sp<android::os::IServiceManager>, readStrongBinder),
    PARCEL_READ_WITH_STATUS(android::sp<android::os::IServiceManager>, readNullableStrongBinder),

    // TODO(b/131868573): can force read of arbitrarily sized vector
    // PARCEL_READ_WITH_STATUS(::std::unique_ptr<std::vector<android::sp<android::IBinder>>>, readStrongBinderVector),
    // PARCEL_READ_WITH_STATUS(::std::optional<std::vector<android::sp<android::IBinder>>>, readStrongBinderVector),
    // PARCEL_READ_WITH_STATUS(std::vector<android::sp<android::IBinder>>, readStrongBinderVector),

    // TODO(b/131868573): can force read of arbitrarily sized vector
    // PARCEL_READ_WITH_STATUS(std::unique_ptr<std::vector<int8_t>>, readByteVector),
    // PARCEL_READ_WITH_STATUS(std::optional<std::vector<int8_t>>, readByteVector),
    // PARCEL_READ_WITH_STATUS(std::vector<int8_t>, readByteVector),
    // PARCEL_READ_WITH_STATUS(std::unique_ptr<std::vector<uint8_t>>, readByteVector),
    // PARCEL_READ_WITH_STATUS(std::optional<std::vector<uint8_t>>, readByteVector),
    // PARCEL_READ_WITH_STATUS(std::vector<uint8_t>, readByteVector),
    // PARCEL_READ_WITH_STATUS(std::unique_ptr<std::vector<int32_t>>, readInt32Vector),
    // PARCEL_READ_WITH_STATUS(std::optional<std::vector<int32_t>>, readInt32Vector),
    // PARCEL_READ_WITH_STATUS(std::vector<int32_t>, readInt32Vector),
    // PARCEL_READ_WITH_STATUS(std::unique_ptr<std::vector<int64_t>>, readInt64Vector),
    // PARCEL_READ_WITH_STATUS(std::optional<std::vector<int64_t>>, readInt64Vector),
    // PARCEL_READ_WITH_STATUS(std::vector<int64_t>, readInt64Vector),
    // PARCEL_READ_WITH_STATUS(std::unique_ptr<std::vector<uint64_t>>, readUint64Vector),
    // PARCEL_READ_WITH_STATUS(std::optional<std::vector<uint64_t>>, readUint64Vector),
    // PARCEL_READ_WITH_STATUS(std::vector<uint64_t>, readUint64Vector),
    // PARCEL_READ_WITH_STATUS(std::unique_ptr<std::vector<float>>, readFloatVector),
    // PARCEL_READ_WITH_STATUS(std::optional<std::vector<float>>, readFloatVector),
    // PARCEL_READ_WITH_STATUS(std::vector<float>, readFloatVector),
    // PARCEL_READ_WITH_STATUS(std::unique_ptr<std::vector<double>>, readDoubleVector),
    // PARCEL_READ_WITH_STATUS(std::optional<std::vector<double>>, readDoubleVector),
    // PARCEL_READ_WITH_STATUS(std::vector<double>, readDoubleVector),
    // PARCEL_READ_WITH_STATUS(std::unique_ptr<std::vector<bool>>, readBoolVector),
    // PARCEL_READ_WITH_STATUS(std::optional<std::vector<bool>>, readBoolVector),
    // PARCEL_READ_WITH_STATUS(std::vector<bool>, readBoolVector),
    // PARCEL_READ_WITH_STATUS(std::unique_ptr<std::vector<char16_t>>, readCharVector),
    // PARCEL_READ_WITH_STATUS(std::optional<std::vector<char16_t>>, readCharVector),
    // PARCEL_READ_WITH_STATUS(std::vector<char16_t>, readCharVector),
    // PARCEL_READ_WITH_STATUS(std::unique_ptr<std::vector<std::unique_ptr<android::String16>>>, readString16Vector),
    // PARCEL_READ_WITH_STATUS(std::optional<std::vector<std::optional<android::String16>>>, readString16Vector),
    // PARCEL_READ_WITH_STATUS(std::vector<android::String16>, readString16Vector),
    // PARCEL_READ_WITH_STATUS(std::unique_ptr<std::vector<std::unique_ptr<std::string>>>, readUtf8VectorFromUtf16Vector),
    // PARCEL_READ_WITH_STATUS(std::optional<std::vector<std::optional<std::string>>>, readUtf8VectorFromUtf16Vector),
    // PARCEL_READ_WITH_STATUS(std::vector<std::string>, readUtf8VectorFromUtf16Vector),

    [] (const android::Parcel& p, uint8_t /*len*/) {
        FUZZ_LOG() << "about to read flattenable";
        ExampleFlattenable f;
        status_t status = p.read(f);
        FUZZ_LOG() << "read flattenable: " << status;
    },
    [] (const android::Parcel& p, uint8_t /*len*/) {
        FUZZ_LOG() << "about to read lite flattenable";
        ExampleLightFlattenable f;
        status_t status = p.read(f);
        FUZZ_LOG() << "read lite flattenable: " << status;
    },

    // TODO(b/131868573): can force read of arbitrarily sized vector
    // TODO: resizeOutVector

    PARCEL_READ_NO_STATUS(int32_t, readExceptionCode),
    [] (const android::Parcel& p, uint8_t /*len*/) {
        FUZZ_LOG() << "about to readNativeHandle";
        native_handle_t* t = p.readNativeHandle();
        FUZZ_LOG() << "readNativeHandle: " << t;
        if (t != nullptr) {
            FUZZ_LOG() << "about to free readNativeHandle";
            native_handle_close(t);
            native_handle_delete(t);
            FUZZ_LOG() << "readNativeHandle freed";
        }
    },
    PARCEL_READ_NO_STATUS(int, readFileDescriptor),
    PARCEL_READ_NO_STATUS(int, readParcelFileDescriptor),
    PARCEL_READ_WITH_STATUS(android::base::unique_fd, readUniqueFileDescriptor),

    // TODO(b/131868573): can force read of arbitrarily sized vector
    // PARCEL_READ_WITH_STATUS(std::unique_ptr<std::vector<android::base::unique_fd>>, readUniqueFileDescriptorVector),
    // PARCEL_READ_WITH_STATUS(std::optional<std::vector<android::base::unique_fd>>, readUniqueFileDescriptorVector),
    // PARCEL_READ_WITH_STATUS(std::vector<android::base::unique_fd>, readUniqueFileDescriptorVector),

    [] (const android::Parcel& p, uint8_t len) {
        FUZZ_LOG() << "about to readBlob";
        ::android::Parcel::ReadableBlob blob;
        status_t status = p.readBlob(len, &blob);
        FUZZ_LOG() << "readBlob status: " << status;
    },
    [] (const android::Parcel& p, uint8_t options) {
        FUZZ_LOG() << "about to readObject";
        bool nullMetaData = options & 0x1;
        const void* obj = static_cast<const void*>(p.readObject(nullMetaData));
        FUZZ_LOG() << "readObject: " << obj;
    },
    PARCEL_READ_NO_STATUS(uid_t, readCallingWorkSourceUid),
    PARCEL_READ_NO_STATUS(size_t, getBlobAshmemSize),
    PARCEL_READ_NO_STATUS(size_t, getOpenAshmemSize),

    // additional parcelable objects defined in libbinder
    [] (const ::android::Parcel& p, uint8_t data) {
        using ::android::os::ParcelableHolder;
        using ::android::Parcelable;
        FUZZ_LOG() << "about to read ParcelableHolder using readParcelable with status";
        Parcelable::Stability stability = Parcelable::Stability::STABILITY_LOCAL;
        if ( (data & 1) == 1 ) {
            stability = Parcelable::Stability::STABILITY_VINTF;
        }
        ParcelableHolder t = ParcelableHolder(stability);
        status_t status = p.readParcelable(&t);
        FUZZ_LOG() << "ParcelableHolder status: " << status;
    },
    PARCEL_READ_WITH_STATUS(android::os::PersistableBundle, readParcelable),
};
// clang-format on
#pragma clang diagnostic pop
