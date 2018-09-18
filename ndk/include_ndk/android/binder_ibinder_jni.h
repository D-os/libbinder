/*
 * Copyright (C) 2018 The Android Open Source Project
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

/**
 * @addtogroup NdkBinder
 * @{
 */

/**
 * @file binder_ibinder_jni.h
 * @brief Conversions between AIBinder and android.os.IBinder
 */

#pragma once

#include <android/binder_ibinder.h>

#include <jni.h>

__BEGIN_DECLS

/**
 * Converts an android.os.IBinder object into an AIBinder* object.
 *
 * If either env or the binder is null, null is returned. If this binder object was originally an
 * AIBinder object, the original object is returned. The returned object has one refcount
 * associated with it, and so this should be accompanied with an AIBinder_decStrong call.
 */
__attribute__((warn_unused_result)) AIBinder* AIBinder_fromJavaBinder(JNIEnv* env, jobject binder);

/**
 * Converts an AIBinder* object into an android.os.IBinder object.
 *
 * If either env or the binder is null, null is returned. If this binder object was originally an
 * IBinder object, the original java object will be returned.
 */
__attribute__((warn_unused_result)) jobject AIBinder_toJavaBinder(JNIEnv* env, AIBinder* binder);

__END_DECLS

/** @} */
