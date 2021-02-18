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
#define LOG_TAG "Stability"

#include <binder/Stability.h>

#include <binder/BpBinder.h>
#include <binder/Binder.h>

namespace android {
namespace internal {

// the libbinder parcel format is currently unstable

// oldest version which is supported
constexpr uint8_t kBinderWireFormatOldest = 1;
// current version
constexpr uint8_t kBinderWireFormatVersion = 1;

Stability::Category Stability::Category::currentFromLevel(Level level) {
    return {
        .version = kBinderWireFormatVersion,
        .reserved = {0},
        .level = level,
    };
}

std::string Stability::Category::debugString() {
    return levelString(level) + " wire protocol version "
        + std::to_string(version);
}

void Stability::markCompilationUnit(IBinder* binder) {
    auto stability = Category::currentFromLevel(getLocalLevel());
    status_t result = setRepr(binder, stability.repr(), true /*log*/);
    LOG_ALWAYS_FATAL_IF(result != OK, "Should only mark known object.");
}

void Stability::markVintf(IBinder* binder) {
    auto stability = Category::currentFromLevel(Level::VINTF);
    status_t result = setRepr(binder, stability.repr(), true /*log*/);
    LOG_ALWAYS_FATAL_IF(result != OK, "Should only mark known object.");
}

void Stability::debugLogStability(const std::string& tag, const sp<IBinder>& binder) {
    auto stability = getCategory(binder.get());
    ALOGE("%s: stability is %s", tag.c_str(), stability.debugString().c_str());
}

void Stability::markVndk(IBinder* binder) {
    auto stability = Category::currentFromLevel(Level::VENDOR);
    status_t result = setRepr(binder, stability.repr(), true /*log*/);
    LOG_ALWAYS_FATAL_IF(result != OK, "Should only mark known object.");
}

bool Stability::requiresVintfDeclaration(const sp<IBinder>& binder) {
    return check(getCategory(binder.get()), Level::VINTF);
}

void Stability::tryMarkCompilationUnit(IBinder* binder) {
    auto stability = Category::currentFromLevel(getLocalLevel());
    (void) setRepr(binder, stability.repr(), false /*log*/);
}

Stability::Level Stability::getLocalLevel() {
#ifdef __ANDROID_VNDK__
    #ifdef __ANDROID_APEX__
        // TODO(b/142684679) avoid use_vendor on system APEXes
        #if !defined(__ANDROID_APEX_COM_ANDROID_MEDIA_SWCODEC__) \
            && !defined(__ANDROID_APEX_TEST_COM_ANDROID_MEDIA_SWCODEC__)
        #error VNDK + APEX only defined for com.android.media.swcodec
        #endif
        // TODO(b/142684679) avoid use_vendor on system APEXes
        return Level::SYSTEM;
    #else
        return Level::VENDOR;
    #endif
#else
    // TODO(b/139325195): split up stability levels for system/APEX.
    return Level::SYSTEM;
#endif
}

status_t Stability::setRepr(IBinder* binder, int32_t representation, bool log) {
    auto current = getCategory(binder);
    auto setting = Category::fromRepr(representation);

    // If we have ahold of a binder with a newer declared version, then it
    // should support older versions, and we will simply write our parcels with
    // the current wire parcel format.
    if (setting.version < kBinderWireFormatOldest) {
        // always log, because this shouldn't happen
        ALOGE("Cannot accept binder with older binder wire protocol version "
              "%u. Versions less than %u are unsupported.", setting.version,
               kBinderWireFormatOldest);
        return BAD_TYPE;
    }

    // null binder is always written w/ 'UNDECLARED' stability
    if (binder == nullptr) {
        if (setting.level == UNDECLARED) {
            return OK;
        } else {
            if (log) {
                ALOGE("Null binder written with stability %s.",
                    levelString(setting.level).c_str());
            }
            return BAD_TYPE;
        }
    }

    if (!isDeclaredLevel(setting.level)) {
        if (log) {
            ALOGE("Can only set known stability, not %u.", setting.level);
        }
        return BAD_TYPE;
    }

    if (current.repr() != 0 && current != setting) {
        if (log) {
            ALOGE("Interface being set with %s but it is already marked as %s",
                  setting.debugString().c_str(),
                  current.debugString().c_str());
        }
        return BAD_TYPE;
    }

    if (current == setting) return OK;

    BBinder* local = binder->localBinder();
    if (local != nullptr) {
        local->mStability = setting.repr();
    } else {
        binder->remoteBinder()->mStability = setting.repr();
    }

    return OK;
}

Stability::Category Stability::getCategory(IBinder* binder) {
    if (binder == nullptr) {
        return Category::currentFromLevel(Level::UNDECLARED);
    }

    BBinder* local = binder->localBinder();
    if (local != nullptr) {
        return Category::fromRepr(local->mStability);
    }

    return Category::fromRepr(binder->remoteBinder()->mStability);
}

bool Stability::check(Category provided, Level required) {
    bool stable = (provided.level & required) == required;

    if (provided.level != UNDECLARED && !isDeclaredLevel(provided.level)) {
        ALOGE("Unknown stability when checking interface stability %d.",
              provided.level);

        stable = false;
    }

    return stable;
}

bool Stability::isDeclaredLevel(Level stability) {
    return stability == VENDOR || stability == SYSTEM || stability == VINTF;
}

std::string Stability::levelString(Level level) {
    switch (level) {
        case Level::UNDECLARED: return "undeclared stability";
        case Level::VENDOR: return "vendor stability";
        case Level::SYSTEM: return "system stability";
        case Level::VINTF: return "vintf stability";
    }
    return "unknown stability " + std::to_string(level);
}

}  // namespace internal
}  // namespace stability
