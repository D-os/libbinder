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

#pragma once

#include <binder/IBinder.h>

using namespace android;

enum Transaction {
    TEST_BOOL = IBinder::FIRST_CALL_TRANSACTION,
    TEST_BYTE,
    TEST_U16,
    TEST_I32,
    TEST_I64,
    TEST_U64,
    TEST_F32,
    TEST_F64,
    TEST_STRING,
    TEST_FILE_DESCRIPTOR,
    TEST_IBINDER,
    TEST_STATUS,
    TEST_FAIL,
};

extern const int8_t TESTDATA_I8[4];
extern const uint8_t TESTDATA_U8[4];
extern const char16_t TESTDATA_CHARS[4];
extern const int32_t TESTDATA_I32[4];
extern const int64_t TESTDATA_I64[4];
extern const uint64_t TESTDATA_U64[4];
extern const float TESTDATA_FLOAT[4];
extern const double TESTDATA_DOUBLE[4];
extern const bool TESTDATA_BOOL[4];
extern const char* const TESTDATA_STRS[4];
