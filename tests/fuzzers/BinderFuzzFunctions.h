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

#include <IBinderFuzzFunctions.h>
#include <fuzzer/FuzzedDataProvider.h>

#include <binder/Binder.h>
#include <binder/IBinder.h>
#include <binder/Parcel.h>
#include <stdint.h>
#include <atomic>

namespace android {

/* This is a vector of lambda functions the fuzzer will pull from.
 *  This is done so new functions can be added to the fuzzer easily
 *  without requiring modifications to the main fuzzer file. This also
 *  allows multiple fuzzers to include this file, if functionality is needed.
 */
static const std::vector<std::function<void(FuzzedDataProvider*, const sp<BBinder>&)>>
        gBBinderOperations = {[](FuzzedDataProvider*, const sp<BBinder>& bbinder) -> void {
                                  bbinder->isRequestingSid();
                              },
                              [](FuzzedDataProvider* fdp, const sp<BBinder>& bbinder) -> void {
                                  bool requestSid = fdp->ConsumeBool();
                                  bbinder->setRequestingSid(requestSid);
                              },
                              [](FuzzedDataProvider*, const sp<BBinder>& bbinder) -> void {
                                  bbinder->getExtension();
                              },
                              [](FuzzedDataProvider*, const sp<BBinder>& bbinder) -> void {
                                  static IBinder* extension = nullptr;
                                  bbinder->setExtension(extension);
                              },
                              [](FuzzedDataProvider* fdp, const sp<BBinder>& bbinder) -> void {
                                  int priority;
                                  int policy = fdp->ConsumeIntegralInRange<int>(0, 2);
                                  if (policy == 0) {
                                      priority = fdp->ConsumeIntegralInRange<int>(-20, 19);
                                  } else {
                                      priority = fdp->ConsumeIntegralInRange<int>(1, 99);
                                  }
                                  bbinder->setMinSchedulerPolicy(policy, priority);
                              },
                              [](FuzzedDataProvider*, const sp<BBinder>& bbinder) -> void {
                                  bbinder->getMinSchedulerPolicy();
                              },
                              [](FuzzedDataProvider*, const sp<BBinder>& bbinder) -> void {
                                  bbinder->getMinSchedulerPriority();
                              },
                              [](FuzzedDataProvider* fdp, const sp<BBinder>& bbinder) -> void {
                                  bool inheritRt = fdp->ConsumeBool();
                                  bbinder->setInheritRt(inheritRt);
                              },
                              [](FuzzedDataProvider*, const sp<BBinder>& bbinder) -> void {
                                  bbinder->isInheritRt();
                              },
                              [](FuzzedDataProvider*, const sp<BBinder>& bbinder) -> void {
                                  bbinder->getDebugPid();
                              }};

} // namespace android
