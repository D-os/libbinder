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

#if defined(__ANDROID_VNDK__)

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

#else  // defined(__ANDROID_VNDK__)

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

#endif  // defined(__ANDROID_VNDK__)

/**
 * This interface has system<->vendor stability
 */
void AIBinder_markVintfStability(AIBinder* binder);

__END_DECLS
