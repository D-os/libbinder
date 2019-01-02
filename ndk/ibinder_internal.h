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

#include <android/binder_ibinder.h>
#include "ibinder_internal.h"

#include <atomic>
#include <mutex>
#include <vector>

#include <binder/Binder.h>
#include <binder/IBinder.h>

inline bool isUserCommand(transaction_code_t code) {
    return code >= FIRST_CALL_TRANSACTION && code <= LAST_CALL_TRANSACTION;
}

struct ABBinder;
struct ABpBinder;

struct AIBinder : public virtual ::android::RefBase {
    explicit AIBinder(const AIBinder_Class* clazz);
    virtual ~AIBinder();

    bool associateClass(const AIBinder_Class* clazz);
    const AIBinder_Class* getClass() const { return mClazz; }

    virtual ::android::sp<::android::IBinder> getBinder() = 0;
    virtual ABBinder* asABBinder() { return nullptr; }
    virtual ABpBinder* asABpBinder() { return nullptr; }

    bool isRemote() const {
        ::android::sp<::android::IBinder> binder = const_cast<AIBinder*>(this)->getBinder();
        return binder->remoteBinder() != nullptr;
    }

   private:
    // AIBinder instance is instance of this class for a local object. In order to transact on a
    // remote object, this also must be set for simplicity (although right now, only the
    // interfaceDescriptor from it is used).
    const AIBinder_Class* mClazz;
};

// This is a local AIBinder object with a known class.
struct ABBinder : public AIBinder, public ::android::BBinder {
    virtual ~ABBinder();

    void* getUserData() { return mUserData; }

    ::android::sp<::android::IBinder> getBinder() override { return this; }
    ABBinder* asABBinder() override { return this; }

    const ::android::String16& getInterfaceDescriptor() const override;
    ::android::status_t onTransact(uint32_t code, const ::android::Parcel& data,
                                   ::android::Parcel* reply, binder_flags_t flags) override;

   private:
    ABBinder(const AIBinder_Class* clazz, void* userData);

    // only thing that should create an ABBinder
    friend AIBinder* AIBinder_new(const AIBinder_Class*, void*);

    // Can contain implementation if this is a local binder. This can still be nullptr for a local
    // binder. If it is nullptr, the implication is the implementation state is entirely external to
    // this object and the functionality provided in the AIBinder_Class is sufficient.
    void* mUserData;
};

// This binder object may be remote or local (even though it is 'Bp'). The implication if it is
// local is that it is an IBinder object created outside of the domain of libbinder_ndk.
struct ABpBinder : public AIBinder, public ::android::BpRefBase {
    // Looks up to see if this object has or is an existing ABBinder or ABpBinder object, otherwise
    // it creates an ABpBinder object.
    static ::android::sp<AIBinder> lookupOrCreateFromBinder(
            const ::android::sp<::android::IBinder>& binder);

    virtual ~ABpBinder();

    void onLastStrongRef(const void* id) override;

    ::android::sp<::android::IBinder> getBinder() override { return remote(); }
    ABpBinder* asABpBinder() override { return this; }

   private:
    explicit ABpBinder(const ::android::sp<::android::IBinder>& binder);
};

struct AIBinder_Class {
    AIBinder_Class(const char* interfaceDescriptor, AIBinder_Class_onCreate onCreate,
                   AIBinder_Class_onDestroy onDestroy, AIBinder_Class_onTransact onTransact);

    const ::android::String16& getInterfaceDescriptor() const { return mInterfaceDescriptor; }

    const AIBinder_Class_onCreate onCreate;
    const AIBinder_Class_onDestroy onDestroy;
    const AIBinder_Class_onTransact onTransact;

   private:
    // This must be a String16 since BBinder virtual getInterfaceDescriptor returns a reference to
    // one.
    const ::android::String16 mInterfaceDescriptor;
};

// Ownership is like this (when linked to death):
//
//   AIBinder_DeathRecipient -sp-> TransferDeathRecipient <-wp-> IBinder
//
// When the AIBinder_DeathRecipient is dropped, so are the actual underlying death recipients. When
// the IBinder dies, only a wp to it is kept.
struct AIBinder_DeathRecipient {
    // One of these is created for every linkToDeath. This is to be able to recover data when a
    // binderDied receipt only gives us information about the IBinder.
    struct TransferDeathRecipient : ::android::IBinder::DeathRecipient {
        TransferDeathRecipient(const ::android::wp<::android::IBinder>& who, void* cookie,
                               const AIBinder_DeathRecipient_onBinderDied& onDied)
            : mWho(who), mCookie(cookie), mOnDied(onDied) {}

        void binderDied(const ::android::wp<::android::IBinder>& who) override;

        const ::android::wp<::android::IBinder>& getWho() { return mWho; }
        void* getCookie() { return mCookie; }

       private:
        ::android::wp<::android::IBinder> mWho;
        void* mCookie;
        const AIBinder_DeathRecipient_onBinderDied& mOnDied;
    };

    explicit AIBinder_DeathRecipient(AIBinder_DeathRecipient_onBinderDied onDied);
    binder_status_t linkToDeath(AIBinder* binder, void* cookie);
    binder_status_t unlinkToDeath(AIBinder* binder, void* cookie);

   private:
    std::mutex mDeathRecipientsMutex;
    std::vector<::android::sp<TransferDeathRecipient>> mDeathRecipients;
    AIBinder_DeathRecipient_onBinderDied mOnDied;
};
