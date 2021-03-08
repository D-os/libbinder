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

#include <fuzzer/FuzzedDataProvider.h>

#include <binder/Parcel.h>
#include <binder/TextOutput.h>
#include "android-base/file.h"
#include "android-base/test_utils.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <cstddef>
#include <limits>

// Fuzzer for the TextOutput class. These were lifted from the existing
// test suite.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    CapturedStderr cap;

    while (fdp.remaining_bytes() > 1) {
        switch (fdp.ConsumeIntegral<uint8_t>() % 3) {
            case 0: {
                std::string input = fdp.ConsumeBytesAsString(
                        fdp.ConsumeIntegralInRange<size_t>(0, fdp.remaining_bytes()));
                android::aerr << input << android::endl;
                break;
            }
            case 1: {
                std::string str = fdp.ConsumeRandomLengthString(fdp.remaining_bytes());
                android::HexDump input(str.c_str(), sizeof(str.c_str()));
                android::aerr << input << android::endl;
                break;
            }
            case 2: {
                android::TypeCode input(fdp.ConsumeIntegral<uint32_t>());
                android::aerr << input << android::endl;
            }
        }
    }
    cap.Stop();

    return 0;
}
