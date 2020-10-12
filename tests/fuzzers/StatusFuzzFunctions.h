/*
 * Copyright 2020 The Android Open Source Project
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

#include <fuzzer/FuzzedDataProvider.h>

#include <binder/Parcel.h>
#include <binder/Status.h>
#include <stdio.h>
#include <utils/String8.h>
#include <cstdint>
#include <sstream>
#include <string>

namespace android {
/* This is a vector of lambda functions the fuzzer will pull from.
 *  This is done so new functions can be added to the fuzzer easily
 *  without requiring modifications to the main fuzzer file. This also
 *  allows multiple fuzzers to include this file, if functionality is needed.
 */
static const std::vector<std::function<void(FuzzedDataProvider*, binder::Status*, Parcel*)>>
        gStatusOperations = {
                [](FuzzedDataProvider*, binder::Status* status, Parcel* parcel) -> void {
                    parcel->setDataPosition(0);
                    status->readFromParcel(*parcel);
                },
                [](FuzzedDataProvider*, binder::Status* status, Parcel* parcel) -> void {
                    status->writeToParcel(parcel);
                },
                [](FuzzedDataProvider* fdp, binder::Status* status, Parcel*) -> void {
                    std::string message_str =
                            fdp->ConsumeRandomLengthString(fdp->remaining_bytes());
                    String8 message(message_str.c_str());
                    status->setServiceSpecificError(fdp->ConsumeIntegral<int32_t>(), message);
                },
                [](FuzzedDataProvider* fdp, binder::Status* status, Parcel*) -> void {
                    std::string message_str =
                            fdp->ConsumeRandomLengthString(fdp->remaining_bytes());
                    String8 message(message_str.c_str());
                    status->setException(fdp->ConsumeIntegral<int32_t>(), message);
                },
                [](FuzzedDataProvider*, binder::Status* status, Parcel*) -> void { status->ok(); },
                [](FuzzedDataProvider* fdp, binder::Status* status, Parcel*) -> void {
                    std::string message_str =
                            fdp->ConsumeRandomLengthString(fdp->remaining_bytes());
                    String8 message(message_str.c_str());
                    *status = binder::Status::fromExceptionCode(fdp->ConsumeIntegral<int32_t>(),
                                                                message);
                },
                [](FuzzedDataProvider* fdp, binder::Status* status, Parcel*) -> void {
                    *status = binder::Status::fromServiceSpecificError(
                            fdp->ConsumeIntegral<int32_t>());
                },
                [](FuzzedDataProvider* fdp, binder::Status*, Parcel*) -> void {
                    binder::Status::exceptionToString(fdp->ConsumeIntegral<int32_t>());
                },
                [](FuzzedDataProvider* fdp, binder::Status* status, Parcel*) -> void {
                    std::string message_str =
                            fdp->ConsumeRandomLengthString(fdp->remaining_bytes());
                    String8 message(message_str.c_str());
                    *status = binder::Status::fromServiceSpecificError(fdp->ConsumeIntegral<
                                                                               int32_t>(),
                                                                       message);
                },
                [](FuzzedDataProvider* fdp, binder::Status* status, Parcel*) -> void {
                    *status = binder::Status::fromStatusT(fdp->ConsumeIntegral<status_t>());
                },
                [](FuzzedDataProvider* fdp, binder::Status* status, Parcel*) -> void {
                    status->setFromStatusT(fdp->ConsumeIntegral<status_t>());
                },
                [](FuzzedDataProvider*, binder::Status* status, Parcel*) -> void {
                    std::stringstream ss;
                    ss << *status;
                },
};

} // namespace android
