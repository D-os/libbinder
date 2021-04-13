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

#include <iostream>

#include <android-base/logging.h>
#include <fuzzbinder/random_parcel.h>
#include <fuzzer/FuzzedDataProvider.h>

#include <cstdlib>
#include <ctime>
#include <sys/resource.h>
#include <sys/time.h>

using android::fillRandomParcel;

void fillRandomParcel(::android::hardware::Parcel* p, FuzzedDataProvider&& provider) {
    // TODO: functionality to create random parcels for libhwbinder parcels
    std::vector<uint8_t> input = provider.ConsumeRemainingBytes<uint8_t>();
    p->setData(input.data(), input.size());
}
static void fillRandomParcel(NdkParcelAdapter* p, FuzzedDataProvider&& provider) {
    // fill underlying parcel using functions to fill random libbinder parcel
    fillRandomParcel(p->parcel(), std::move(provider));
}

template <typename P>
void doFuzz(const char* backend, const std::vector<ParcelRead<P>>& reads,
            FuzzedDataProvider&& provider) {
    // Allow some majority of the bytes to be dedicated to telling us what to
    // do. The fixed value added here represents that we want to test doing a
    // lot of 'instructions' even on really short parcels.
    size_t maxInstructions = 20 + (provider.remaining_bytes() * 2 / 3);
    // but don't always use that many instructions. We want to allow the fuzzer
    // to explore large parcels with few instructions if it wants to.
    std::vector<uint8_t> instructions = provider.ConsumeBytes<uint8_t>(
            provider.ConsumeIntegralInRange<size_t>(0, maxInstructions));

    P p;
    fillRandomParcel(&p, std::move(provider));

    // since we are only using a byte to index
    CHECK(reads.size() <= 255) << reads.size();

    FUZZ_LOG() << "backend: " << backend;
    FUZZ_LOG() << "input: " << hexString(p.data(), p.dataSize());
    FUZZ_LOG() << "instructions: " << hexString(instructions);

    for (size_t i = 0; i + 1 < instructions.size(); i += 2) {
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

size_t getHardMemoryLimit() {
    struct rlimit limit;
    CHECK(0 == getrlimit(RLIMIT_AS, &limit)) << errno;
    return limit.rlim_max;
}

void setMemoryLimit(size_t cur, size_t max) {
    const struct rlimit kLimit = {
       .rlim_cur = cur,
       .rlim_max = max,
    };
    CHECK(0 == setrlimit(RLIMIT_AS, &kLimit)) << errno;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static constexpr size_t kMemLimit = 1 * 1024 * 1024;
    size_t hardLimit = getHardMemoryLimit();
    setMemoryLimit(std::min(kMemLimit, hardLimit), hardLimit);

    if (size <= 1) return 0;  // no use

    // avoid timeouts, see b/142617274, b/142473153
    if (size > 50000) return 0;

    FuzzedDataProvider provider = FuzzedDataProvider(data, size);

    const std::function<void(FuzzedDataProvider &&)> fuzzBackend[3] = {
            [](FuzzedDataProvider&& provider) {
                doFuzz<::android::hardware::Parcel>("hwbinder", HWBINDER_PARCEL_READ_FUNCTIONS,
                                                    std::move(provider));
            },
            [](FuzzedDataProvider&& provider) {
                doFuzz<::android::Parcel>("binder", BINDER_PARCEL_READ_FUNCTIONS,
                                          std::move(provider));
            },
            [](FuzzedDataProvider&& provider) {
                doFuzz<NdkParcelAdapter>("binder_ndk", BINDER_NDK_PARCEL_READ_FUNCTIONS,
                                         std::move(provider));
            },
    };

    provider.PickValueInArray(fuzzBackend)(std::move(provider));

    setMemoryLimit(hardLimit, hardLimit);

    return 0;
}
