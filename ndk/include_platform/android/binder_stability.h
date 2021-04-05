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

#include <android/binder_ibinder.h>

__BEGIN_DECLS

/**
 * Private addition to binder_flag_t.
 */
enum {
    /**
     * Indicates that this transaction is coupled w/ vendor.img
     */
    FLAG_PRIVATE_VENDOR = 0x10000000,
};

#if defined(__ANDROID_VENDOR__)

enum {
    FLAG_PRIVATE_LOCAL = FLAG_PRIVATE_VENDOR,
};

/**
 * This interface has the stability of the vendor image.
 */
void AIBinder_markVendorStability(AIBinder* binder);

static inline void AIBinder_markCompilationUnitStability(AIBinder* binder) {
    AIBinder_markVendorStability(binder);
}

/**
 * Given a binder interface at a certain stability, there may be some
 * requirements associated with that higher stability level. For instance, a
 * VINTF stability binder is required to be in the VINTF manifest. This API
 * can be called to use that same interface within the vendor partition.
 */
void AIBinder_forceDowngradeToVendorStability(AIBinder* binder);

static inline void AIBinder_forceDowngradeToLocalStability(AIBinder* binder) {
    AIBinder_forceDowngradeToVendorStability(binder);
}

#else  // defined(__ANDROID_VENDOR__)

enum {
    FLAG_PRIVATE_LOCAL = 0,
};

/**
 * This interface has the stability of the system image.
 */
__attribute__((weak)) void AIBinder_markSystemStability(AIBinder* binder);

static inline void AIBinder_markCompilationUnitStability(AIBinder* binder) {
    if (AIBinder_markSystemStability == nullptr) return;

    AIBinder_markSystemStability(binder);
}

/**
 * Given a binder interface at a certain stability, there may be some
 * requirements associated with that higher stability level. For instance, a
 * VINTF stability binder is required to be in the VINTF manifest. This API
 * can be called to use that same interface within the system partition.
 */
void AIBinder_forceDowngradeToSystemStability(AIBinder* binder);

static inline void AIBinder_forceDowngradeToLocalStability(AIBinder* binder) {
    AIBinder_forceDowngradeToSystemStability(binder);
}

#endif  // defined(__ANDROID_VENDOR__)

/**
 * WARNING: this is not expected to be used manually. When the build system has
 * versioned checks in place for an interface that prevent it being changed year
 * over year (specifically like those for @VintfStability stable AIDL
 * interfaces), this could be called. Calling this without this or equivalent
 * infrastructure will lead to de facto frozen APIs or GSI test failures.
 *
 * This interface has system<->vendor stability
 */
void AIBinder_markVintfStability(AIBinder* binder);

__END_DECLS
