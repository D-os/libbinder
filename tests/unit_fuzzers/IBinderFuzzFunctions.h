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

namespace android {

class FuzzDeathRecipient : public IBinder::DeathRecipient {
private:
    virtual void binderDied(const wp<IBinder>& who) { (void)who; };
};

// Allow objects to be attached that aren't stack locals
static uint32_t objectID = 0;
static uint32_t object = 0;
static uint32_t cleanup_cookie = 0;

/* This is a vector of lambda functions the fuzzer will pull from.
 *  This is done so new functions can be added to the fuzzer easily
 *  without requiring modifications to the main fuzzer file. This also
 *  allows multiple fuzzers to include this file, if functionality is needed.
 */
static const std::vector<std::function<void(FuzzedDataProvider*, IBinder*)>> gIBinderOperations =
        {[](FuzzedDataProvider*, IBinder* ibinder) -> void { ibinder->getInterfaceDescriptor(); },
         [](FuzzedDataProvider*, IBinder* ibinder) -> void { ibinder->isBinderAlive(); },
         [](FuzzedDataProvider*, IBinder* ibinder) -> void { ibinder->pingBinder(); },
         [](FuzzedDataProvider* fdp, IBinder* ibinder) -> void {
             int fd = STDOUT_FILENO;
             std::string rand_str = fdp->ConsumeRandomLengthString(fdp->remaining_bytes());
             Vector<String16> args;
             args.push(String16(rand_str.c_str()));
             ibinder->dump(fd, args);
         },
         [](FuzzedDataProvider* fdp, IBinder* ibinder) -> void {
             objectID = fdp->ConsumeIntegral<uint32_t>();
             object = fdp->ConsumeIntegral<uint32_t>();
             cleanup_cookie = fdp->ConsumeIntegral<uint32_t>();
             IBinder::object_cleanup_func func = IBinder::object_cleanup_func();
             ibinder->attachObject(fdp->ConsumeBool() ? reinterpret_cast<void*>(&objectID)
                                                      : nullptr,
                                   fdp->ConsumeBool() ? reinterpret_cast<void*>(&object) : nullptr,
                                   fdp->ConsumeBool() ? reinterpret_cast<void*>(&cleanup_cookie)
                                                      : nullptr,
                                   func);
         },
         [](FuzzedDataProvider* fdp, IBinder* ibinder) -> void {
             uint32_t id = fdp->ConsumeIntegral<uint32_t>();
             ibinder->findObject(reinterpret_cast<void*>(&id));
         },
         [](FuzzedDataProvider* fdp, IBinder* ibinder) -> void {
             uint32_t id = fdp->ConsumeIntegral<uint32_t>();
             ibinder->detachObject(reinterpret_cast<void*>(&id));
         },
         [](FuzzedDataProvider* fdp, IBinder* ibinder) -> void {
             uint32_t code = fdp->ConsumeIntegral<uint32_t>();
             Parcel p_data;
             Parcel reply;
             uint32_t flags = fdp->ConsumeIntegral<uint32_t>();
             ibinder->transact(code, p_data, &reply, flags);
         }};
} // namespace android
