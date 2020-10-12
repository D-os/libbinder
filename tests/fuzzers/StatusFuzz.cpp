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

#include <StatusFuzzFunctions.h>
#include <binder/Parcel.h>
#include <binder/Status.h>
#include <commonFuzzHelpers.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <utils/String8.h>
#include <cstdint>
#include <sstream>
#include <string>

namespace android {
// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    int32_t exceptionCode = fdp.ConsumeIntegral<int32_t>();
    std::string message_str = fdp.ConsumeRandomLengthString(fdp.remaining_bytes());
    String8 message(message_str.c_str());

    Parcel parcel;
    std::vector<uint8_t> buf = fdp.ConsumeBytes<uint8_t>(
            fdp.ConsumeIntegralInRange<size_t>(0, fdp.remaining_bytes() - 1));
    parcel.write(buf.data(), buf.size());
    binder::Status status = binder::Status::fromExceptionCode(exceptionCode, message);

    while (fdp.remaining_bytes() > 0) {
        callArbitraryFunction(&fdp, gStatusOperations, &status, &parcel);
    }
    return 0;
}
} // namespace android
