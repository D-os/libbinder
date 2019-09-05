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
#define FUZZ_LOG_TAG "main"

#include "binder.h"
#include "hwbinder.h"
#include "util.h"

#include <android-base/logging.h>

#include <cstdlib>
#include <ctime>

template <typename P>
void doFuzz(
        const std::vector<ParcelRead<P>>& reads,
        const std::vector<uint8_t>& input,
        const std::vector<uint8_t>& instructions) {

    P p;
    p.setData(input.data(), input.size());

    for (size_t i = 0; i < instructions.size() - 1; i += 2) {
        uint8_t a = instructions[i];
        uint8_t b = instructions[i + 1];

        FUZZ_LOG() << "size: " << p.dataSize() << " avail: " << p.dataAvail()
                   << " pos: " << p.dataPosition() << " cap: " << p.dataCapacity();

        reads[a % reads.size()](p, b);
    }
}

void fuzz(uint8_t options, const std::vector<uint8_t>& input, const std::vector<uint8_t>& instructions) {
    (void) options;

    // although they will do completely different things, might as well fuzz both
    doFuzz<::android::hardware::Parcel>(HWBINDER_PARCEL_READ_FUNCTIONS, input, instructions);
    doFuzz<::android::Parcel>(BINDER_PARCEL_READ_FUNCTIONS, input, instructions);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size <= 1) return 0;  // no use
    uint8_t options = *data;
    data++;
    size--;

    // TODO: generate 'objects' data

    // data to fill out parcel
    size_t inputLen = size / 2;
    std::vector<uint8_t> input(data, data + inputLen);
    data += inputLen;
    size -= inputLen;

    // data to use to determine what to do
    size_t instructionLen = size;
    std::vector<uint8_t> instructions(data, data + instructionLen);
    data += instructionLen;
    size -= instructionLen;

    CHECK(size == 0) << "size: " << size;

    FUZZ_LOG() << "options: " << (int)options << " inputLen: " << inputLen << " instructionLen: " << instructionLen;
    FUZZ_LOG() << "input: " << hexString(input);
    FUZZ_LOG() << "instructions: " << hexString(instructions);

    fuzz(options, input, instructions);
    return 0;
}
