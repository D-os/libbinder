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

#include <binder/Parcel.h>
#include <binder/IPCThreadState.h>
#include <gtest/gtest.h>

using android::IPCThreadState;
using android::OK;
using android::Parcel;
using android::String16;
using android::String8;
using android::status_t;

// Tests a second operation results in a parcel at the same location as it
// started.
void parcelOpSameLength(const std::function<void(Parcel*)>& a, const std::function<void(Parcel*)>& b) {
    Parcel p;
    a(&p);
    size_t end = p.dataPosition();
    p.setDataPosition(0);
    b(&p);
    EXPECT_EQ(end, p.dataPosition());
}

TEST(Parcel, InverseInterfaceToken) {
    const String16 token = String16("asdf");
    parcelOpSameLength([&] (Parcel* p) {
        p->writeInterfaceToken(token);
    }, [&] (Parcel* p) {
        EXPECT_TRUE(p->enforceInterface(token, IPCThreadState::self()));
    });
}

TEST(Parcel, Utf8FromUtf16Read) {
    const char* token = "asdf";
    parcelOpSameLength([&] (Parcel* p) {
        p->writeString16(String16(token));
    }, [&] (Parcel* p) {
        std::string s;
        EXPECT_EQ(OK, p->readUtf8FromUtf16(&s));
        EXPECT_EQ(token, s);
    });
}

TEST(Parcel, Utf8AsUtf16Write) {
    std::string token = "asdf";
    parcelOpSameLength([&] (Parcel* p) {
        p->writeUtf8AsUtf16(token);
    }, [&] (Parcel* p) {
        String16 s;
        EXPECT_EQ(OK, p->readString16(&s));
        EXPECT_EQ(s, String16(token.c_str()));
    });
}

template <typename T>
using readFunc = status_t (Parcel::*)(T* out) const;
template <typename T>
using writeFunc = status_t (Parcel::*)(const T& in);
template <typename T>
using copyWriteFunc = status_t (Parcel::*)(T in);

template <typename T, typename WRITE_FUNC>
void readWriteInverse(std::vector<T>&& ts, readFunc<T> r, WRITE_FUNC w) {
    for (const T& value : ts) {
        parcelOpSameLength([&] (Parcel* p) {
            (*p.*w)(value);
        }, [&] (Parcel* p) {
            T outValue;
            EXPECT_EQ(OK, (*p.*r)(&outValue));
            EXPECT_EQ(value, outValue);
        });
    }
}

template <typename T>
void readWriteInverse(std::vector<T>&& ts, readFunc<T> r, writeFunc<T> w) {
    readWriteInverse<T, writeFunc<T>>(std::move(ts), r, w);
}
template <typename T>
void readWriteInverse(std::vector<T>&& ts, readFunc<T> r, copyWriteFunc<T> w) {
    readWriteInverse<T, copyWriteFunc<T>>(std::move(ts), r, w);
}

#define TEST_READ_WRITE_INVERSE(type, name, ...) \
    TEST(Parcel, Inverse##name) { \
        readWriteInverse<type>(__VA_ARGS__, &Parcel::read##name, &Parcel::write##name); \
    }

TEST_READ_WRITE_INVERSE(int32_t, Int32, {-2, -1, 0, 1, 2});
TEST_READ_WRITE_INVERSE(uint32_t, Uint32, {0, 1, 2});
TEST_READ_WRITE_INVERSE(int64_t, Int64, {-2, -1, 0, 1, 2});
TEST_READ_WRITE_INVERSE(uint64_t, Uint64, {0, 1, 2});
TEST_READ_WRITE_INVERSE(float, Float, {-1.0f, 0.0f, 3.14f});
TEST_READ_WRITE_INVERSE(double, Double, {-1.0, 0.0, 3.14});
TEST_READ_WRITE_INVERSE(bool, Bool, {true, false});
TEST_READ_WRITE_INVERSE(char16_t, Char, {u'a', u'\0'});
TEST_READ_WRITE_INVERSE(int8_t, Byte, {-1, 0, 1});
TEST_READ_WRITE_INVERSE(String8, String8, {String8(), String8("a"), String8("asdf")});
TEST_READ_WRITE_INVERSE(String16, String16, {String16(), String16("a"), String16("asdf")});
