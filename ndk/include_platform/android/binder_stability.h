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

#if defined(__ANDROID_VNDK__) && !defined(__ANDROID_APEX__)

/**
 * This interface has the stability of the vendor image.
 */
void AIBinder_markVendorStability(AIBinder* binder);

static inline void AIBinder_markCompilationUnitStability(AIBinder* binder) {
    AIBinder_markVendorStability(binder);
}

#else  // defined(__ANDROID_VNDK__) && !defined(__ANDROID_APEX__)

/**
 * This interface has the stability of the system image.
 */
void AIBinder_markSystemStability(AIBinder* binder);

static inline void AIBinder_markCompilationUnitStability(AIBinder* binder) {
    AIBinder_markSystemStability(binder);
}

#endif  // defined(__ANDROID_VNDK__) && !defined(__ANDROID_APEX__)

/**
 * This interface has system<->vendor stability
 */
void AIBinder_markVintfStability(AIBinder* binder);

__END_DECLS
