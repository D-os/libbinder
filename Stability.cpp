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

#include <binder/BpBinder.h>
#include <binder/Binder.h>

namespace android {
namespace internal {

void Stability::markCompilationUnit(IBinder* binder) {
    status_t result = set(binder, kLocalStability, true /*log*/);
    LOG_ALWAYS_FATAL_IF(result != OK, "Should only mark known object.");
}

void Stability::markVintf(IBinder* binder) {
    status_t result = set(binder, Level::VINTF, true /*log*/);
    LOG_ALWAYS_FATAL_IF(result != OK, "Should only mark known object.");
}

void Stability::debugLogStability(const std::string& tag, const sp<IBinder>& binder) {
    ALOGE("%s: stability is %s", tag.c_str(), stabilityString(get(binder.get())).c_str());
}

void Stability::markVndk(IBinder* binder) {
    status_t result = set(binder, Level::VENDOR, true /*log*/);
    LOG_ALWAYS_FATAL_IF(result != OK, "Should only mark known object.");
}

bool Stability::requiresVintfDeclaration(const sp<IBinder>& binder) {
    return check(get(binder.get()), Level::VINTF);
}

void Stability::tryMarkCompilationUnit(IBinder* binder) {
    (void) set(binder, kLocalStability, false /*log*/);
}

status_t Stability::set(IBinder* binder, int32_t stability, bool log) {
    Level currentStability = get(binder);

    // null binder is always written w/ 'UNDECLARED' stability
    if (binder == nullptr) {
        if (stability == UNDECLARED) {
            return OK;
        } else {
            if (log) {
                ALOGE("Null binder written with stability %s.",
                    stabilityString(stability).c_str());
            }
            return BAD_TYPE;
        }
    }

    if (!isDeclaredStability(stability)) {
        if (log) {
            ALOGE("Can only set known stability, not %d.", stability);
        }
        return BAD_TYPE;
    }

    if (currentStability != Level::UNDECLARED && currentStability != stability) {
        if (log) {
            ALOGE("Interface being set with %s but it is already marked as %s.",
                stabilityString(stability).c_str(), stabilityString(currentStability).c_str());
        }
        return BAD_TYPE;
    }

    if (currentStability == stability) return OK;

    BBinder* local = binder->localBinder();
    if (local != nullptr) {
        local->mStability = static_cast<int32_t>(stability);
    } else {
        binder->remoteBinder()->mStability = static_cast<int32_t>(stability);
    }

    return OK;
}

Stability::Level Stability::get(IBinder* binder) {
    if (binder == nullptr) return UNDECLARED;

    BBinder* local = binder->localBinder();
    if (local != nullptr) {
        return static_cast<Stability::Level>(local->mStability);
    }

    return static_cast<Stability::Level>(binder->remoteBinder()->mStability);
}

bool Stability::check(int32_t provided, Level required) {
    bool stable = (provided & required) == required;

    if (!isDeclaredStability(provided) && provided != UNDECLARED) {
        ALOGE("Unknown stability when checking interface stability %d.", provided);

        stable = false;
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
