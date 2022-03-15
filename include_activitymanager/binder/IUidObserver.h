/*
 * Copyright (C) 2017 The Android Open Source Project
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

#ifndef __ANDROID_VNDK__

#include <binder/IInterface.h>

namespace android {

// ----------------------------------------------------------------------

class IUidObserver : public IInterface
{
public:
    DECLARE_META_INTERFACE(UidObserver)

    virtual void onUidGone(uid_t uid, bool disabled) = 0;
    virtual void onUidActive(uid_t uid) = 0;
    virtual void onUidIdle(uid_t uid, bool disabled) = 0;
    virtual void onUidStateChanged(uid_t uid, int32_t procState, int64_t procStateSeq,
                                   int32_t capability) = 0;
    virtual void onUidProcAdjChanged(uid_t uid) = 0;

    enum {
        ON_UID_GONE_TRANSACTION = IBinder::FIRST_CALL_TRANSACTION,
        ON_UID_ACTIVE_TRANSACTION,
        ON_UID_IDLE_TRANSACTION,
        ON_UID_STATE_CHANGED_TRANSACTION,
        ON_UID_PROC_ADJ_CHANGED_TRANSACTION
    };
};

// ----------------------------------------------------------------------

class BnUidObserver : public BnInterface<IUidObserver>
{
public:
    // NOLINTNEXTLINE(google-default-arguments)
    virtual status_t  onTransact(uint32_t code,
                                 const Parcel& data,
                                 Parcel* reply,
                                 uint32_t flags = 0);
};

// ----------------------------------------------------------------------

} // namespace android

#else // __ANDROID_VNDK__
#error "This header is not visible to vendors"
#endif // __ANDROID_VNDK__
