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

#include <binder/Parcel.h>
#include <fuzzer/FuzzedDataProvider.h>

#include <functional>
#include <vector>

namespace android {

struct RandomParcelOptions {
    std::function<void(Parcel* p, FuzzedDataProvider& provider)> writeHeader;
    std::vector<sp<IBinder>> extraBinders;
    std::vector<base::unique_fd> extraFds;
};

/**
 * Fill parcel data, including some random binder objects and FDs
 *
 * p - the Parcel to fill
 * provider - takes ownership and completely consumes provider
 * writeHeader - optional function to write a specific header once the format of the parcel is
 *     picked (for instance, to write an interface header)
 */
void fillRandomParcel(Parcel* p, FuzzedDataProvider&& provider, const RandomParcelOptions& = {});
} // namespace android
