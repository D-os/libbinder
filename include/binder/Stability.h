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

#pragma once

#include <binder/IBinder.h>
#include <string>

namespace android {

class BpBinder;
class ProcessState;

namespace internal {

// WARNING: These APIs are only ever expected to be called by auto-generated code.
//     Instead of calling them, you should set the stability of a .aidl interface
class Stability final {
public:
    // WARNING: This is only ever expected to be called by auto-generated code. You likely want to
    // change or modify the stability class of the interface you are using.
    // This must be called as soon as the binder in question is constructed. No thread safety
    // is provided.
    // E.g. stability is according to libbinder compilation unit
    static void markCompilationUnit(IBinder* binder);
    // WARNING: This is only ever expected to be called by auto-generated code. You likely want to
    // change or modify the stability class of the interface you are using.
    // This must be called as soon as the binder in question is constructed. No thread safety
    // is provided.
    // E.g. stability is according to libbinder_ndk or Java SDK AND the interface
    //     expressed here is guaranteed to be stable for multiple years (Stable AIDL)
    static void markVintf(IBinder* binder);

    // WARNING: for debugging only
    static void debugLogStability(const std::string& tag, const sp<IBinder>& binder);

    // WARNING: This is only ever expected to be called by auto-generated code or tests.
    // You likely want to change or modify the stability of the interface you are using.
    // This must be called as soon as the binder in question is constructed. No thread safety
    // is provided.
    // E.g. stability is according to libbinder_ndk or Java SDK AND the interface
    //     expressed here is guaranteed to be stable for multiple years (Stable AIDL)
    // If this is called when __ANDROID_VNDK__ is not defined, then it is UB and will likely
    // break the device during GSI or other tests.
    static void markVndk(IBinder* binder);

    // Returns true if the binder needs to be declared in the VINTF manifest or
    // else false if the binder is local to the current partition.
    static bool requiresVintfDeclaration(const sp<IBinder>& binder);
private:
    // Parcel needs to read/write stability level in an unstable format.
    friend ::android::Parcel;

    // only expose internal APIs inside of libbinder, for checking stability
    friend ::android::BpBinder;

    // so that it can mark the context object (only the root object doesn't go
    // through Parcel)
    friend ::android::ProcessState;

    static void tryMarkCompilationUnit(IBinder* binder);

    enum Level : int32_t {
        UNDECLARED = 0,

        VENDOR = 0b000011,
        SYSTEM = 0b001100,
        VINTF = 0b111111,
    };

#if defined(__ANDROID_VNDK__) && !defined(__ANDROID_APEX__)
    static constexpr Level kLocalStability = Level::VENDOR;
#else
    static constexpr Level kLocalStability = Level::SYSTEM;
#endif

    // applies stability to binder if stability level is known
    __attribute__((warn_unused_result))
    static status_t set(IBinder* binder, int32_t stability, bool log);

    static Level get(IBinder* binder);

    static bool check(int32_t provided, Level required);

    static bool isDeclaredStability(int32_t stability);
    static std::string stabilityString(int32_t stability);

    Stability();
};

}  // namespace internal
}  // namespace android
