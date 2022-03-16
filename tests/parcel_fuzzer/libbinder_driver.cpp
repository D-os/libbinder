/*
 * Copyright (C) 2022 The Android Open Source Project
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
#include <fuzzbinder/libbinder_driver.h>

#include <fuzzbinder/random_parcel.h>

namespace android {

void fuzzService(const sp<IBinder>& binder, FuzzedDataProvider&& provider) {
    while (provider.remaining_bytes() > 0) {
        uint32_t code = provider.ConsumeIntegral<uint32_t>();
        uint32_t flags = provider.ConsumeIntegral<uint32_t>();
        Parcel data;

        std::vector<uint8_t> subData = provider.ConsumeBytes<uint8_t>(
                provider.ConsumeIntegralInRange<size_t>(0, provider.remaining_bytes()));
        fillRandomParcel(&data, FuzzedDataProvider(subData.data(), subData.size()),
                         [&binder](Parcel* p, FuzzedDataProvider& provider) {
                             // most code will be behind checks that the head of the Parcel
                             // is exactly this, so make it easier for fuzzers to reach this
                             if (provider.ConsumeBool()) {
                                 p->writeInterfaceToken(binder->getInterfaceDescriptor());
                             }
                         });

        Parcel reply;
        (void)binder->transact(code, data, &reply, flags);
    }
}

} // namespace android
