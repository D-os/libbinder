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

#pragma once

#include <stdint.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

// Keep the exception codes in sync with android/os/Parcel.java.
enum {
    EX_NONE = 0,
    EX_SECURITY = -1,
    EX_BAD_PARCELABLE = -2,
    EX_ILLEGAL_ARGUMENT = -3,
    EX_NULL_POINTER = -4,
    EX_ILLEGAL_STATE = -5,
    EX_NETWORK_MAIN_THREAD = -6,
    EX_UNSUPPORTED_OPERATION = -7,
    EX_SERVICE_SPECIFIC = -8,
    EX_PARCELABLE = -9,

    /**
     * This is special and Java specific; see Parcel.java.
     * This should be considered a success, and the next readInt32 bytes can be ignored.
     */
    EX_HAS_REPLY_HEADER = -128,

    /**
     * This is special, and indicates to native binder proxies that the
     * transaction has failed at a low level.
     */
    EX_TRANSACTION_FAILED = -129,
};

/**
 * One of the above values or -errno.
 * By convention, positive values are considered to mean service-specific exceptions.
 */
typedef int32_t binder_status_t;

__END_DECLS
