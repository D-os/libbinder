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

#include <binder/BpBinder.h>
#include <binder/IBinder.h>
#include <binder/IPCThreadState.h>
#include <binder/IResultReceiver.h>
#include <binder/Parcel.h>
#include <binder/Stability.h>

#include <cutils/compiler.h>
#include <utils/KeyedVector.h>
#include <utils/Log.h>
#include <utils/Mutex.h>
#include <utils/threads.h>

#include <stdio.h>

namespace android {

// Static variable to reference so we don't consume a bunch of memory to link and
// unlink DeathRecipients.
static int8_t kBpBinderCookie = 0;

/* This is a vector of lambda functions the fuzzer will pull from.
 *  This is done so new functions can be added to the fuzzer easily
 *  without requiring modifications to the main fuzzer file. This also
 *  allows multiple fuzzers to include this file, if functionality is needed.
 */
static const std::vector<std::function<void(FuzzedDataProvider*, const sp<BpBinder>&,
                                            const sp<IBinder::DeathRecipient>&)>>
        gBPBinderOperations =
                {[](FuzzedDataProvider* fdp, const sp<BpBinder>& bpbinder,
                    const sp<IBinder::DeathRecipient>& s_recipient) -> void {
                     // Clean up possible leftover memory.
                     wp<IBinder::DeathRecipient> outRecipient(nullptr);
                     bpbinder->sendObituary();
                     bpbinder->unlinkToDeath(nullptr, reinterpret_cast<void*>(&kBpBinderCookie), 0,
                                             &outRecipient);

                     uint32_t flags = fdp->ConsumeIntegral<uint32_t>();
                     kBpBinderCookie = fdp->ConsumeIntegral<int8_t>();
                     bpbinder->linkToDeath(s_recipient.get(),
                                           reinterpret_cast<void*>(&kBpBinderCookie), flags);
                 },
                 [](FuzzedDataProvider* fdp, const sp<BpBinder>& bpbinder,
                    const sp<IBinder::DeathRecipient>&) -> void {
                     wp<IBinder::DeathRecipient> out_recipient(nullptr);
                     uint32_t flags = fdp->ConsumeIntegral<uint32_t>();
                     int8_t random_cookie = fdp->ConsumeIntegral<int8_t>();
                     bpbinder->unlinkToDeath(nullptr, reinterpret_cast<void*>(&random_cookie),
                                             flags, &out_recipient);
                 },
                 [](FuzzedDataProvider*, const sp<BpBinder>& bpbinder,
                    const sp<IBinder::DeathRecipient>&) -> void { bpbinder->remoteBinder(); },
                 [](FuzzedDataProvider*, const sp<BpBinder>& bpbinder,
                    const sp<IBinder::DeathRecipient>&) -> void { bpbinder->sendObituary(); },
                 [](FuzzedDataProvider* fdp, const sp<BpBinder>& bpbinder,
                    const sp<IBinder::DeathRecipient>&) -> void {
                     uint32_t uid = fdp->ConsumeIntegral<uint32_t>();
                     bpbinder->getBinderProxyCount(uid);
                 },
                 [](FuzzedDataProvider*, const sp<BpBinder>& bpbinder,
                    const sp<IBinder::DeathRecipient>&) -> void { bpbinder->enableCountByUid(); },
                 [](FuzzedDataProvider*, const sp<BpBinder>& bpbinder,
                    const sp<IBinder::DeathRecipient>&) -> void { bpbinder->disableCountByUid(); },
                 [](FuzzedDataProvider*, const sp<BpBinder>& bpbinder,
                    const sp<IBinder::DeathRecipient>&) -> void {
                     Vector<uint32_t> uids;
                     Vector<uint32_t> counts;
                     bpbinder->getCountByUid(uids, counts);
                 },
                 [](FuzzedDataProvider* fdp, const sp<BpBinder>& bpbinder,
                    const sp<IBinder::DeathRecipient>&) -> void {
                     bool enable = fdp->ConsumeBool();
                     bpbinder->setCountByUidEnabled(enable);
                 },
                 [](FuzzedDataProvider*, const sp<BpBinder>& bpbinder,
                    const sp<IBinder::DeathRecipient>&) -> void {
                     binder_proxy_limit_callback cb = binder_proxy_limit_callback();
                     bpbinder->setLimitCallback(cb);
                 },
                 [](FuzzedDataProvider* fdp, const sp<BpBinder>& bpbinder,
                    const sp<IBinder::DeathRecipient>&) -> void {
                     int high = fdp->ConsumeIntegral<int>();
                     int low = fdp->ConsumeIntegral<int>();
                     bpbinder->setBinderProxyCountWatermarks(high, low);
                 }};

} // namespace android
