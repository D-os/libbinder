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
#include "binder_ndk.h"
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

    // since we are only using a byte to index
    CHECK(reads.size() <= 255) << reads.size();

    for (size_t i = 0; i < instructions.size() - 1; i += 2) {
        uint8_t a = instructions[i];
        uint8_t readIdx = a % reads.size();

        uint8_t b = instructions[i + 1];

        FUZZ_LOG() << "Instruction: " << (i / 2) + 1 << "/" << instructions.size() / 2
                   << " cmd: " << static_cast<size_t>(a) << " (" << static_cast<size_t>(readIdx)
                   << ") arg: " << static_cast<size_t>(b) << " size: " << p.dataSize()
                   << " avail: " << p.dataAvail() << " pos: " << p.dataPosition()
                   << " cap: " << p.dataCapacity();

        reads[readIdx](p, b);
    }
}

void fuzz(uint8_t options, const std::vector<uint8_t>& input, const std::vector<uint8_t>& instructions) {
    uint8_t parcelType = options & 0x3;

    switch (parcelType) {
        case 0x0:
            doFuzz<::android::hardware::Parcel>(HWBINDER_PARCEL_READ_FUNCTIONS, input,
                                                instructions);
            break;
        case 0x1:
            doFuzz<::android::Parcel>(BINDER_PARCEL_READ_FUNCTIONS, input, instructions);
            break;
        case 0x2:
            doFuzz<NdkParcelAdapter>(BINDER_NDK_PARCEL_READ_FUNCTIONS, input, instructions);
            break;
        case 0x3:
            /*reserved for future use*/
            break;
        default:
            LOG_ALWAYS_FATAL("unknown parcel type %d", static_cast<int>(parcelType));
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size <= 1) return 0;  // no use

    // avoid timeouts, see b/142617274, b/142473153
    if (size > 50000) return 0;

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
