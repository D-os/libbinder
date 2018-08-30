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
#include "AIBinder_internal.h"

#include <atomic>

#include <binder/Binder.h>
#include <binder/IBinder.h>

inline bool isUserCommand(transaction_code_t code) {
    return code >= FIRST_CALL_TRANSACTION && code <= LAST_CALL_TRANSACTION;
}

struct ABBinder;
struct ABpBinder;

struct AIBinder : public virtual ::android::RefBase {
    AIBinder(const AIBinder_Class* clazz);
    virtual ~AIBinder();

    // This returns an AIBinder object with this class associated. If the class is already
    // associated, 'this' will be returned. If there is a local AIBinder implementation, that will
    // be returned. If this is a remote object, the class will be associated and this will be ready
    // to be used for transactions.
    ::android::sp<AIBinder> associateClass(const AIBinder_Class* clazz);
    const AIBinder_Class* getClass() const { return mClazz; }

    // This does not create the binder if it does not exist in the process.
    virtual ::android::sp<::android::IBinder> getBinder() = 0;
    virtual ABBinder* asABBinder() { return nullptr; }
    virtual ABpBinder* asABpBinder() { return nullptr; }

    bool isRemote() {
        auto binder = getBinder();
        // if the binder is nullptr, then it is a local object which hasn't been sent out of process
        // yet.
        return binder != nullptr && binder->remoteBinder() != nullptr;
    }

private:
    // AIBinder instance is instance of this class for a local object. In order to transact on a
    // remote object, this also must be set for simplicity (although right now, only the
    // interfaceDescriptor from it is used).
    const AIBinder_Class* mClazz;
};

// This is a local AIBinder object with a known class.
struct ABBinder : public AIBinder, public ::android::BBinder {
    ABBinder(const AIBinder_Class* clazz, void* userData);
    virtual ~ABBinder();

    void* getUserData() { return mUserData; }

    ::android::sp<::android::IBinder> getBinder() override { return this; }
    ABBinder* asABBinder() override { return this; }

    const ::android::String16& getInterfaceDescriptor() const override;
    binder_status_t onTransact(uint32_t code, const ::android::Parcel& data,
                               ::android::Parcel* reply, binder_flags_t flags) override;

private:
    // Can contain implementation if this is a local binder. This can still be nullptr for a local
    // binder. If it is nullptr, the implication is the implementation state is entirely external to
    // this object and the functionality provided in the AIBinder_Class is sufficient.
    void* mUserData;
};

// This binder object may be remote or local (even though it is 'Bp'). It is not yet associated with
// a class.
struct ABpBinder : public AIBinder, public ::android::BpRefBase {
    ABpBinder(::android::sp<::android::IBinder> binder);
    virtual ~ABpBinder();

    ::android::sp<::android::IBinder> getBinder() override { return remote(); }
    ABpBinder* asABpBinder() override { return this; }
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
