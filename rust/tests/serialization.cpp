/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <android/binder_ibinder_platform.h>
#include <android/binder_libbinder.h>
#include <binder/IServiceManager.h>
#include <binder/Parcel.h>
#include <binder/ParcelFileDescriptor.h>
#include <binder/ProcessState.h>
#include <binder/Status.h>
#include <gtest/gtest.h>
#include <utils/Errors.h>
#include <utils/String16.h>
#include "android-base/file.h"
#include "serialization.hpp"

#include <cmath>
#include <cstdint>
#include <iostream>
#include <optional>

using namespace std;
using namespace android;
using android::base::unique_fd;
using android::os::ParcelFileDescriptor;

// defined in Rust
extern "C" AIBinder *rust_service();


const int8_t TESTDATA_I8[4] = {-128, 0, 117, 127};
const uint8_t TESTDATA_U8[4] = {0, 42, 117, 255};
const char16_t TESTDATA_CHARS[4] = {0, 42, 117, numeric_limits<char16_t>::max()};
const int32_t TESTDATA_I32[4] = {numeric_limits<int32_t>::min(), 0, 117, numeric_limits<int32_t>::max()};
const int64_t TESTDATA_I64[4] = {numeric_limits<int64_t>::min(), 0, 117, numeric_limits<int64_t>::max()};
const uint64_t TESTDATA_U64[4] = {0, 42, 117, numeric_limits<uint64_t>::max()};
const float TESTDATA_FLOAT[4] = {
        numeric_limits<float>::quiet_NaN(),
        -numeric_limits<float>::infinity(),
        117.0,
        numeric_limits<float>::infinity(),
};
const double TESTDATA_DOUBLE[4] = {
        numeric_limits<double>::quiet_NaN(),
        -numeric_limits<double>::infinity(),
        117.0,
        numeric_limits<double>::infinity(),
};
const bool TESTDATA_BOOL[4] = {true, false, false, true};
const char* const TESTDATA_STRS[4] = {"", nullptr, "test", ""};

static ::testing::Environment* gEnvironment;

class SerializationEnvironment : public ::testing::Environment {
public:
    void SetUp() override {
        m_server = AIBinder_toPlatformBinder(rust_service());
    }

    sp<IBinder> getServer(void) { return m_server; }

private:
    sp<IBinder> m_server;
};


class SerializationTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_NE(gEnvironment, nullptr);
        m_server = static_cast<SerializationEnvironment *>(gEnvironment)->getServer();
    }

    sp<IBinder> m_server;
};


TEST_F(SerializationTest, SerializeBool) {
    android::Parcel data;
    data.writeInterfaceToken(String16("read_parcel_test"));

    vector<bool> bools(begin(TESTDATA_BOOL), end(TESTDATA_BOOL));
    ASSERT_EQ(data.writeBool(true), OK);
    ASSERT_EQ(data.writeBool(false), OK);
    ASSERT_EQ(data.writeBoolVector(bools), OK);
    ASSERT_EQ(data.writeBoolVector(nullopt), OK);

    android::Parcel reply;
    ASSERT_EQ(m_server->transact(TEST_BOOL, data, &reply), OK);

    vector<bool> read_bools;
    optional<vector<bool>> maybe_bools;
    ASSERT_EQ(reply.readBool(), true);
    ASSERT_EQ(reply.readBool(), false);
    ASSERT_EQ(reply.readBoolVector(&read_bools), OK);
    ASSERT_EQ(read_bools, bools);
    ASSERT_EQ(reply.readBoolVector(&maybe_bools), OK);
    ASSERT_EQ(maybe_bools, nullopt);

    int32_t end;
    ASSERT_EQ(reply.readInt32(&end), NOT_ENOUGH_DATA);
}

TEST_F(SerializationTest, SerializeByte) {
    android::Parcel data;
    data.writeInterfaceToken(String16("read_parcel_test"));

    vector<int8_t> i8s(begin(TESTDATA_I8), end(TESTDATA_I8));
    vector<uint8_t> u8s(begin(TESTDATA_U8), end(TESTDATA_U8));
    data.writeByte(0);
    data.writeByte(1);
    data.writeByte(numeric_limits<int8_t>::max());
    data.writeByteVector(i8s);
    data.writeByteVector(u8s);
    data.writeByteVector(optional<vector<int8_t>>({}));

    android::Parcel reply;
    ASSERT_EQ(m_server->transact(TEST_BYTE, data, &reply), OK);

    vector<int8_t> read_i8s;
    vector<uint8_t> read_u8s;
    optional<vector<int8_t>> maybe_i8s;
    ASSERT_EQ(reply.readByte(), 0);
    ASSERT_EQ(reply.readByte(), 1);
    ASSERT_EQ(reply.readByte(), numeric_limits<int8_t>::max());
    ASSERT_EQ(reply.readByteVector(&read_i8s), OK);
    ASSERT_EQ(read_i8s, i8s);
    ASSERT_EQ(reply.readByteVector(&read_u8s), OK);
    ASSERT_EQ(read_u8s, u8s);
    ASSERT_EQ(reply.readByteVector(&maybe_i8s), OK);
    ASSERT_EQ(maybe_i8s, nullopt);

    int32_t end;
    ASSERT_EQ(reply.readInt32(&end), NOT_ENOUGH_DATA);
}

TEST_F(SerializationTest, SerializeU16) {
    android::Parcel data;
    data.writeInterfaceToken(String16("read_parcel_test"));

    vector<char16_t> chars(begin(TESTDATA_CHARS), end(TESTDATA_CHARS));
    data.writeChar(0);
    data.writeChar(1);
    data.writeChar(numeric_limits<char16_t>::max());
    data.writeCharVector(chars);
    data.writeCharVector(nullopt);

    android::Parcel reply;
    ASSERT_EQ(m_server->transact(TEST_U16, data, &reply), OK);

    vector<char16_t> read_chars;
    optional<vector<char16_t>> maybe_chars;
    ASSERT_EQ(reply.readChar(), 0);
    ASSERT_EQ(reply.readChar(), 1);
    ASSERT_EQ(reply.readChar(), numeric_limits<char16_t>::max());
    ASSERT_EQ(reply.readCharVector(&read_chars), OK);
    ASSERT_EQ(read_chars, chars);
    ASSERT_EQ(reply.readCharVector(&maybe_chars), OK);
    ASSERT_EQ(maybe_chars, nullopt);

    int32_t end;
    ASSERT_EQ(reply.readInt32(&end), NOT_ENOUGH_DATA);
}

TEST_F(SerializationTest, SerializeI32) {
    android::Parcel data;
    data.writeInterfaceToken(String16("read_parcel_test"));

    vector<int32_t> i32s(begin(TESTDATA_I32), end(TESTDATA_I32));
    data.writeInt32(0);
    data.writeInt32(1);
    data.writeInt32(numeric_limits<int32_t>::max());
    data.writeInt32Vector(i32s);
    data.writeInt32Vector(nullopt);

    android::Parcel reply;
    ASSERT_EQ(m_server->transact(TEST_I32, data, &reply), OK);

    vector<int32_t> read_i32s;
    optional<vector<int32_t>> maybe_i32s;
    ASSERT_EQ(reply.readInt32(), 0);
    ASSERT_EQ(reply.readInt32(), 1);
    ASSERT_EQ(reply.readInt32(), numeric_limits<int32_t>::max());
    ASSERT_EQ(reply.readInt32Vector(&read_i32s), OK);
    ASSERT_EQ(read_i32s, i32s);
    ASSERT_EQ(reply.readInt32Vector(&maybe_i32s), OK);
    ASSERT_EQ(maybe_i32s, nullopt);

    int32_t end;
    ASSERT_EQ(reply.readInt32(&end), NOT_ENOUGH_DATA);
}

TEST_F(SerializationTest, SerializeI64) {
    android::Parcel data;
    data.writeInterfaceToken(String16("read_parcel_test"));

    vector<int64_t> i64s(begin(TESTDATA_I64), end(TESTDATA_I64));
    data.writeInt64(0);
    data.writeInt64(1);
    data.writeInt64(numeric_limits<int64_t>::max());
    data.writeInt64Vector(i64s);
    data.writeInt64Vector(nullopt);

    android::Parcel reply;
    ASSERT_EQ(m_server->transact(TEST_I64, data, &reply), OK);

    vector<int64_t> read_i64s;
    optional<vector<int64_t>> maybe_i64s;
    ASSERT_EQ(reply.readInt64(), 0);
    ASSERT_EQ(reply.readInt64(), 1);
    ASSERT_EQ(reply.readInt64(), numeric_limits<int64_t>::max());
    ASSERT_EQ(reply.readInt64Vector(&read_i64s), OK);
    ASSERT_EQ(read_i64s, i64s);
    ASSERT_EQ(reply.readInt64Vector(&maybe_i64s), OK);
    ASSERT_EQ(maybe_i64s, nullopt);

    int32_t end;
    ASSERT_EQ(reply.readInt32(&end), NOT_ENOUGH_DATA);
}

TEST_F(SerializationTest, SerializeU64) {
    android::Parcel data;
    data.writeInterfaceToken(String16("read_parcel_test"));

    vector<uint64_t> u64s(begin(TESTDATA_U64), end(TESTDATA_U64));
    data.writeUint64(0);
    data.writeUint64(1);
    data.writeUint64(numeric_limits<uint64_t>::max());
    data.writeUint64Vector(u64s);
    data.writeUint64Vector(nullopt);

    android::Parcel reply;
    ASSERT_EQ(m_server->transact(TEST_U64, data, &reply), OK);

    vector<uint64_t> read_u64s;
    optional<vector<uint64_t>> maybe_u64s;
    ASSERT_EQ(reply.readUint64(), 0);
    ASSERT_EQ(reply.readUint64(), 1);
    ASSERT_EQ(reply.readUint64(), numeric_limits<uint64_t>::max());
    ASSERT_EQ(reply.readUint64Vector(&read_u64s), OK);
    ASSERT_EQ(read_u64s, u64s);
    ASSERT_EQ(reply.readUint64Vector(&maybe_u64s), OK);
    ASSERT_EQ(maybe_u64s, nullopt);

    int32_t end;
    ASSERT_EQ(reply.readInt32(&end), NOT_ENOUGH_DATA);
}

TEST_F(SerializationTest, SerializeF32) {
    android::Parcel data;
    data.writeInterfaceToken(String16("read_parcel_test"));

    vector<float> floats(begin(TESTDATA_FLOAT), end(TESTDATA_FLOAT));
    data.writeFloat(0);
    data.writeFloatVector(floats);
    data.writeFloatVector(nullopt);

    android::Parcel reply;
    ASSERT_EQ(m_server->transact(TEST_F32, data, &reply), OK);

    vector<float> read_floats;
    optional<vector<float>> maybe_floats;
    ASSERT_EQ(reply.readFloat(), 0);
    ASSERT_EQ(reply.readFloatVector(&read_floats), OK);
    ASSERT_TRUE(isnan(read_floats[0]));
    ASSERT_EQ(read_floats[1], floats[1]);
    ASSERT_EQ(read_floats[2], floats[2]);
    ASSERT_EQ(read_floats[3], floats[3]);
    ASSERT_EQ(reply.readFloatVector(&maybe_floats), OK);
    ASSERT_EQ(maybe_floats, nullopt);

    int32_t end;
    ASSERT_EQ(reply.readInt32(&end), NOT_ENOUGH_DATA);
}

TEST_F(SerializationTest, SerializeF64) {
    android::Parcel data;
    data.writeInterfaceToken(String16("read_parcel_test"));

    vector<double> doubles(begin(TESTDATA_DOUBLE), end(TESTDATA_DOUBLE));
    data.writeDouble(0);
    data.writeDoubleVector(doubles);
    data.writeDoubleVector(nullopt);

    android::Parcel reply;
    ASSERT_EQ(m_server->transact(TEST_F64, data, &reply), OK);

    vector<double> read_doubles;
    optional<vector<double>> maybe_doubles;
    ASSERT_EQ(reply.readDouble(), 0);
    ASSERT_EQ(reply.readDoubleVector(&read_doubles), OK);
    ASSERT_TRUE(isnan(read_doubles[0]));
    ASSERT_EQ(read_doubles[1], doubles[1]);
    ASSERT_EQ(read_doubles[2], doubles[2]);
    ASSERT_EQ(read_doubles[3], doubles[3]);
    ASSERT_EQ(reply.readDoubleVector(&maybe_doubles), OK);
    ASSERT_EQ(maybe_doubles, nullopt);

    int32_t end;
    ASSERT_EQ(reply.readInt32(&end), NOT_ENOUGH_DATA);
}

TEST_F(SerializationTest, SerializeString) {
    android::Parcel data;
    data.writeInterfaceToken(String16("read_parcel_test"));

    vector<optional<String16>> strings;
    for (auto I = begin(TESTDATA_STRS), E = end(TESTDATA_STRS); I != E; ++I) {
        if (*I == nullptr) {
            strings.push_back(optional<String16>());
        } else {
            strings.emplace_back(*I);
        }
    }
    data.writeUtf8AsUtf16(string("testing"));
    data.writeString16(nullopt);
    data.writeString16Vector(strings);
    data.writeString16Vector(nullopt);

    android::Parcel reply;
    ASSERT_EQ(m_server->transact(TEST_STRING, data, &reply), OK);

    optional<String16> maybe_string;
    optional<vector<optional<String16>>> read_strings;
    ASSERT_EQ(reply.readString16(), String16("testing"));
    ASSERT_EQ(reply.readString16(&maybe_string), OK);
    ASSERT_EQ(maybe_string, nullopt);
    ASSERT_EQ(reply.readString16Vector(&read_strings), OK);
    ASSERT_EQ(read_strings, strings);
    ASSERT_EQ(reply.readString16Vector(&read_strings), OK);
    ASSERT_EQ(read_strings, nullopt);

    int32_t end;
    ASSERT_EQ(reply.readInt32(&end), NOT_ENOUGH_DATA);
}

TEST_F(SerializationTest, SerializeFileDescriptor) {
    unique_fd out_file, in_file;
    ASSERT_TRUE(base::Pipe(&out_file, &in_file));

    vector<ParcelFileDescriptor> file_descriptors;
    file_descriptors.push_back(ParcelFileDescriptor(std::move(out_file)));
    file_descriptors.push_back(ParcelFileDescriptor(std::move(in_file)));

    android::Parcel data;
    data.writeInterfaceToken(String16("read_parcel_test"));

    data.writeParcelable(file_descriptors[0]);
    data.writeParcelable(file_descriptors[1]);
    data.writeParcelableVector(file_descriptors);

    android::Parcel reply;
    ASSERT_EQ(m_server->transact(TEST_FILE_DESCRIPTOR, data, &reply), OK);

    ParcelFileDescriptor returned_fd1, returned_fd2;
    vector<ParcelFileDescriptor> returned_file_descriptors;
    ASSERT_EQ(reply.readParcelable(&returned_fd1), OK);
    ASSERT_EQ(reply.readParcelable(&returned_fd2), OK);
    ASSERT_EQ(reply.readParcelableVector(&returned_file_descriptors), OK);

    int32_t end;
    ASSERT_EQ(reply.readInt32(&end), NOT_ENOUGH_DATA);

    base::WriteStringToFd("Testing", returned_fd2.get());
    base::WriteStringToFd("File", returned_file_descriptors[1].get());
    base::WriteStringToFd("Descriptors", file_descriptors[1].get());

    string expected = "TestingFileDescriptors";
    vector<char> buf(expected.length());
    base::ReadFully(file_descriptors[0].release(), buf.data(), buf.size());
    ASSERT_EQ(expected, string(buf.data()));
}

TEST_F(SerializationTest, SerializeIBinder) {
    android::Parcel data;
    data.writeInterfaceToken(String16("read_parcel_test"));

    data.writeStrongBinder(m_server);
    data.writeStrongBinder(nullptr);
    data.writeStrongBinderVector({m_server, nullptr});
    data.writeStrongBinderVector(nullopt);

    android::Parcel reply;
    ASSERT_EQ(m_server->transact(TEST_IBINDER, data, &reply), OK);

    optional<vector<sp<IBinder>>> binders;
    ASSERT_TRUE(reply.readStrongBinder());
    ASSERT_FALSE(reply.readStrongBinder());
    ASSERT_EQ(reply.readStrongBinderVector(&binders), OK);
    ASSERT_EQ(binders->size(), 2);
    ASSERT_TRUE((*binders)[0]);
    ASSERT_FALSE((*binders)[1]);
    ASSERT_EQ(reply.readStrongBinderVector(&binders), OK);
    ASSERT_FALSE(binders);

    int32_t end;
    ASSERT_EQ(reply.readInt32(&end), NOT_ENOUGH_DATA);
}

TEST_F(SerializationTest, SerializeStatus) {
    android::Parcel data;
    data.writeInterfaceToken(String16("read_parcel_test"));

    binder::Status::ok().writeToParcel(&data);
    binder::Status::fromExceptionCode(binder::Status::EX_NULL_POINTER, "a status message")
            .writeToParcel(&data);
    binder::Status::fromServiceSpecificError(42, "a service-specific error").writeToParcel(&data);

    android::Parcel reply;
    ASSERT_EQ(m_server->transact(TEST_STATUS, data, &reply), OK);

    binder::Status status;

    ASSERT_EQ(status.readFromParcel(reply), OK);
    ASSERT_TRUE(status.isOk());

    ASSERT_EQ(status.readFromParcel(reply), OK);
    ASSERT_EQ(status.exceptionCode(), binder::Status::EX_NULL_POINTER);
    ASSERT_EQ(status.exceptionMessage(), "a status message");

    ASSERT_EQ(status.readFromParcel(reply), OK);
    ASSERT_EQ(status.serviceSpecificErrorCode(), 42);
    ASSERT_EQ(status.exceptionMessage(), "a service-specific error");

    int32_t end;
    ASSERT_EQ(reply.readInt32(&end), NOT_ENOUGH_DATA);
}

// Test that failures from Rust properly propagate to C++
TEST_F(SerializationTest, SerializeRustFail) {
    android::Parcel data;
    data.writeInterfaceToken(String16("read_parcel_test"));
    ASSERT_EQ(m_server->transact(TEST_FAIL, data, nullptr), FAILED_TRANSACTION);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    gEnvironment = AddGlobalTestEnvironment(new SerializationEnvironment());
    ProcessState::self()->startThreadPool();
    return RUN_ALL_TESTS();
}
