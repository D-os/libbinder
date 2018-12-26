/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef ANDROID_BINDER_KERNEL_H
#define ANDROID_BINDER_KERNEL_H

#include <linux/android/binder.h>

/**
 * This file exists because the uapi kernel headers in bionic are built
 * from upstream kernel headers only, and not all of the hwbinder kernel changes
 * have made it upstream yet. Therefore, the modifications to the
 * binder header are added locally in this file.
 */

enum {
        FLAT_BINDER_FLAG_TXN_SECURITY_CTX = 0x1000,
};

#define BINDER_SET_CONTEXT_MGR_EXT      _IOW('b', 13, struct flat_binder_object)

struct binder_transaction_data_secctx {
        struct binder_transaction_data transaction_data;
        binder_uintptr_t secctx;
};

enum {
        BR_TRANSACTION_SEC_CTX = _IOR('r', 2,
                              struct binder_transaction_data_secctx),
};

#endif // ANDROID_BINDER_KERNEL_H
