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

#pragma once

#include <binder/IBinder.h>
#include <fuzzer/FuzzedDataProvider.h>

namespace android {
/**
 * Based on the random data in provider, construct an arbitrary number of
 * Parcel objects and send them to the service in serial.
 *
 * Usage:
 *
 *   extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
 *       FuzzedDataProvider provider = FuzzedDataProvider(data, size);
 *       // can use provider here to create a service with different options
 *       sp<IFoo> myService = sp<IFoo>::make(...);
 *       fuzzService(myService, std::move(provider));
 *   }
 */
void fuzzService(const sp<IBinder>& binder, FuzzedDataProvider&& provider);
} // namespace android
