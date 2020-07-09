/*
 * Copyright (C) 2020 The Android Open Source Project
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
 * Makes calls to AIBinder_getCallingSid work if the kernel supports it. This
 * must be called on a local binder server before it is sent out to any othe
 * process. If this is a remote binder, it will abort. If the kernel doesn't
 * support this feature, you'll always get null from AIBinder_getCallingSid.
 *
 * \param binder local server binder to request security contexts on
 */
void AIBinder_setRequestingSid(AIBinder* binder, bool requestingSid) __INTRODUCED_IN(31);

/**
 * Returns the selinux context of the callee.
 *
 * In order for this to work, the following conditions must be met:
 * - The kernel must be new enough to support this feature.
 * - The server must have called AIBinder_setRequestingSid.
 * - The callee must be a remote process.
 *
 * \return security context or null if unavailable. The lifetime of this context
 * is the lifetime of the transaction.
 */
__attribute__((warn_unused_result)) const char* AIBinder_getCallingSid() __INTRODUCED_IN(31);

__END_DECLS
