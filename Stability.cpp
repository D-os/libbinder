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

#include <binder/Stability.h>

namespace android {
namespace internal {

void Stability::markCompilationUnit(IBinder* binder) {
#ifdef __ANDROID_VNDK__
constexpr Stability::Level kLocalStability = Stability::Level::VENDOR;
#else
constexpr Stability::Level kLocalStability = Stability::Level::SYSTEM;
#endif

    status_t result = set(binder, kLocalStability);
    LOG_ALWAYS_FATAL_IF(result != OK, "Should only mark known object.");
}

void Stability::markVintf(IBinder* binder) {
    status_t result = set(binder, Level::VINTF);
    LOG_ALWAYS_FATAL_IF(result != OK, "Should only mark known object.");
}

status_t Stability::set(IBinder* binder, int32_t stability) {
    Level currentStability = get(binder);

    // null binder is always written w/ 'UNDECLARED' stability
    if (binder == nullptr) {
        if (stability == UNDECLARED) {
            return OK;
        } else {
            ALOGE("Null binder written with stability %s.", stabilityString(stability).c_str());
            return BAD_TYPE;
        }
    }

    if (!isDeclaredStability(stability)) {
        // There are UNDECLARED sets because some binder interfaces don't set their stability, and
        // then UNDECLARED stability is sent on the other side.
        if (stability != UNDECLARED) {
            ALOGE("Can only set known stability, not %d.", stability);
            return BAD_TYPE;
        }
    }

    if (currentStability != Level::UNDECLARED && currentStability != stability) {
        ALOGE("Interface being set with %s but it is already marked as %s.",
            stabilityString(stability).c_str(), stabilityString(stability).c_str());
        return BAD_TYPE;
    }

    if (currentStability == stability) return OK;

    binder->attachObject(
        reinterpret_cast<void*>(&Stability::get),
        reinterpret_cast<void*>(stability),
        nullptr /*cleanupCookie*/,
        nullptr /*cleanup function*/);

    return OK;
}

Stability::Level Stability::get(IBinder* binder) {
    if (binder == nullptr) return UNDECLARED;

    return static_cast<Level>(reinterpret_cast<intptr_t>(
        binder->findObject(reinterpret_cast<void*>(&Stability::get))));
}

bool Stability::check(int32_t provided, Level required) {
    bool stable = (provided & required) == required;

    if (!isDeclaredStability(provided) && provided != UNDECLARED) {
        ALOGE("Unknown stability when checking interface stability %d.", provided);

        stable = false;
    }

    if (!stable) {
        ALOGE("Interface with %s cannot accept interface with %s.",
            stabilityString(required).c_str(),
            stabilityString(provided).c_str());
    }

    return stable;
}

bool Stability::isDeclaredStability(int32_t stability) {
    return stability == VENDOR || stability == SYSTEM || stability == VINTF;
}

std::string Stability::stabilityString(int32_t stability) {
    switch (stability) {
        case Level::UNDECLARED: return "undeclared stability";
        case Level::VENDOR: return "vendor stability";
        case Level::SYSTEM: return "system stability";
        case Level::VINTF: return "vintf stability";
    }
    return "unknown stability " + std::to_string(stability);
}

}  // namespace internal
}  // namespace stability