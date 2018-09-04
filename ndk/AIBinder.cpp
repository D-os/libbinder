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

#include <android/binder_ibinder.h>
#include "AIBinder_internal.h"

#include <android/binder_status.h>
#include "AParcel_internal.h"

#include <android-base/logging.h>

using ::android::IBinder;
using ::android::Parcel;
using ::android::sp;
using ::android::String16;
using ::android::wp;

namespace ABBinderTag {

static const void* kId = "ABBinder";
static void* kValue = static_cast<void*>(new bool{true});
void cleanId(const void* /*id*/, void* /*obj*/, void* /*cookie*/){/* do nothing */};

static void attach(const sp<IBinder>& binder) {
    binder->attachObject(kId, kValue, nullptr /*cookie*/, cleanId);
}
static bool has(const sp<IBinder>& binder) {
    return binder != nullptr && binder->findObject(kId) == kValue;
}

} // namespace ABBinderTag

AIBinder::AIBinder(const AIBinder_Class* clazz) : mClazz(clazz) {}
AIBinder::~AIBinder() {}

bool AIBinder::associateClass(const AIBinder_Class* clazz) {
    using ::android::String8;

    if (clazz == nullptr) return false;
    if (mClazz == clazz) return true;

    String8 newDescriptor(clazz->getInterfaceDescriptor());

    if (mClazz != nullptr) {
        String8 currentDescriptor(mClazz->getInterfaceDescriptor());
        if (newDescriptor == currentDescriptor) {
            LOG(ERROR) << __func__ << ": Class descriptors '" << currentDescriptor
                       << "' match during associateClass, but they are different class objects. "
                          "Class descriptor collision?";
        } else {
            LOG(ERROR) << __func__
                       << ": Class cannot be associated on object which already has a class. "
                          "Trying to associate to '"
                       << newDescriptor.c_str() << "' but already set to '"
                       << currentDescriptor.c_str() << "'.";
        }

        // always a failure because we know mClazz != clazz
        return false;
    }

    CHECK(asABpBinder() != nullptr); // ABBinder always has a descriptor

    String8 descriptor(getBinder()->getInterfaceDescriptor());
    if (descriptor != newDescriptor) {
        LOG(ERROR) << __func__ << ": Expecting binder to have class '" << newDescriptor.c_str()
                   << "' but descriptor is actually '" << descriptor.c_str() << "'.";
        return false;
    }

    // if this is a local object, it's not one known to libbinder_ndk
    mClazz = clazz;

    return true;
}

ABBinder::ABBinder(const AIBinder_Class* clazz, void* userData)
      : AIBinder(clazz), BBinder(), mUserData(userData) {
    CHECK(clazz != nullptr);
}
ABBinder::~ABBinder() {
    getClass()->onDestroy(mUserData);
}

const String16& ABBinder::getInterfaceDescriptor() const {
    return getClass()->getInterfaceDescriptor();
}

binder_status_t ABBinder::onTransact(transaction_code_t code, const Parcel& data, Parcel* reply,
                                     binder_flags_t flags) {
    if (isUserCommand(code)) {
        if (!data.checkInterface(this)) {
            return EX_ILLEGAL_STATE;
        }

        const AParcel in = AParcel::readOnly(this, &data);
        AParcel out = AParcel(this, reply, false /*owns*/);

        return getClass()->onTransact(this, code, &in, &out);
    } else {
        return BBinder::onTransact(code, data, reply, flags);
    }
}

ABpBinder::ABpBinder(const ::android::sp<::android::IBinder>& binder)
      : AIBinder(nullptr /*clazz*/), BpRefBase(binder) {
    CHECK(binder != nullptr);
}
ABpBinder::~ABpBinder() {}

sp<AIBinder> ABpBinder::fromBinder(const ::android::sp<::android::IBinder>& binder) {
    if (binder == nullptr) {
        return nullptr;
    }
    if (ABBinderTag::has(binder)) {
        return static_cast<ABBinder*>(binder.get());
    }
    return new ABpBinder(binder);
}

struct AIBinder_Weak {
    wp<AIBinder> binder;
};
AIBinder_Weak* AIBinder_Weak_new(AIBinder* binder) {
    if (binder == nullptr) {
        return nullptr;
    }

    return new AIBinder_Weak{wp<AIBinder>(binder)};
}
void AIBinder_Weak_delete(AIBinder_Weak** weakBinder) {
    if (weakBinder == nullptr) {
        return;
    }

    delete *weakBinder;
    *weakBinder = nullptr;
}
AIBinder* AIBinder_Weak_promote(AIBinder_Weak* weakBinder) {
    if (weakBinder == nullptr) {
        return nullptr;
    }

    sp<AIBinder> binder = weakBinder->binder.promote();
    AIBinder_incStrong(binder.get());
    return binder.get();
}

AIBinder_Class::AIBinder_Class(const char* interfaceDescriptor, AIBinder_Class_onCreate onCreate,
                               AIBinder_Class_onDestroy onDestroy,
                               AIBinder_Class_onTransact onTransact)
      : onCreate(onCreate),
        onDestroy(onDestroy),
        onTransact(onTransact),
        mInterfaceDescriptor(interfaceDescriptor) {}

AIBinder_Class* AIBinder_Class_define(const char* interfaceDescriptor,
                                      AIBinder_Class_onCreate onCreate,
                                      AIBinder_Class_onDestroy onDestroy,
                                      AIBinder_Class_onTransact onTransact) {
    if (interfaceDescriptor == nullptr || onCreate == nullptr || onDestroy == nullptr ||
        onTransact == nullptr) {
        return nullptr;
    }

    return new AIBinder_Class(interfaceDescriptor, onCreate, onDestroy, onTransact);
}

AIBinder* AIBinder_new(const AIBinder_Class* clazz, void* args) {
    if (clazz == nullptr) {
        LOG(ERROR) << __func__ << ": Must provide class to construct local binder.";
        return nullptr;
    }

    void* userData = clazz->onCreate(args);

    sp<AIBinder> ret = new ABBinder(clazz, userData);
    ABBinderTag::attach(ret->getBinder());

    AIBinder_incStrong(ret.get());
    return ret.get();
}

bool AIBinder_isRemote(const AIBinder* binder) {
    if (binder == nullptr) {
        return true;
    }

    return binder->isRemote();
}

void AIBinder_incStrong(AIBinder* binder) {
    if (binder == nullptr) {
        LOG(ERROR) << __func__ << ": on null binder";
        return;
    }

    binder->incStrong(nullptr);
}
void AIBinder_decStrong(AIBinder* binder) {
    if (binder == nullptr) {
        LOG(ERROR) << __func__ << ": on null binder";
        return;
    }

    binder->decStrong(nullptr);
}
int32_t AIBinder_debugGetRefCount(AIBinder* binder) {
    if (binder == nullptr) {
        LOG(ERROR) << __func__ << ": on null binder";
        return -1;
    }

    return binder->getStrongCount();
}

bool AIBinder_associateClass(AIBinder* binder, const AIBinder_Class* clazz) {
    if (binder == nullptr) {
        return false;
    }

    return binder->associateClass(clazz);
}

const AIBinder_Class* AIBinder_getClass(AIBinder* binder) {
    if (binder == nullptr) {
        return nullptr;
    }

    return binder->getClass();
}

void* AIBinder_getUserData(AIBinder* binder) {
    if (binder == nullptr) {
        return nullptr;
    }

    ABBinder* bBinder = binder->asABBinder();
    if (bBinder == nullptr) {
        return nullptr;
    }

    return bBinder->getUserData();
}

binder_status_t AIBinder_prepareTransaction(AIBinder* binder, AParcel** in) {
    if (binder == nullptr || in == nullptr) {
        LOG(ERROR) << __func__ << ": requires non-null parameters.";
        return EX_NULL_POINTER;
    }
    const AIBinder_Class* clazz = binder->getClass();
    if (clazz == nullptr) {
        LOG(ERROR) << __func__
                   << ": Class must be defined for a remote binder transaction. See "
                      "AIBinder_associateClass.";
        return EX_ILLEGAL_STATE;
    }

    *in = new AParcel(binder);
    binder_status_t status = (**in)->writeInterfaceToken(clazz->getInterfaceDescriptor());
    if (status != EX_NONE) {
        delete *in;
        *in = nullptr;
    }

    return status;
}

binder_status_t AIBinder_transact(AIBinder* binder, transaction_code_t code, AParcel** in,
                                  AParcel** out, binder_flags_t flags) {
    if (in == nullptr) {
        LOG(ERROR) << __func__ << ": requires non-null in parameter";
        return EX_NULL_POINTER;
    }

    using AutoParcelDestroyer = std::unique_ptr<AParcel*, void (*)(AParcel**)>;
    // This object is the input to the transaction. This function takes ownership of it and deletes
    // it.
    AutoParcelDestroyer forIn(in, AParcel_delete);

    if (!isUserCommand(code)) {
        LOG(ERROR) << __func__ << ": Only user-defined transactions can be made from the NDK.";
        return EX_UNSUPPORTED_OPERATION;
    }

    if ((flags & ~FLAG_ONEWAY) != 0) {
        LOG(ERROR) << __func__ << ": Unrecognized flags sent: " << flags;
        return EX_ILLEGAL_ARGUMENT;
    }

    if (binder == nullptr || *in == nullptr || out == nullptr) {
        LOG(ERROR) << __func__ << ": requires non-null parameters.";
        return EX_NULL_POINTER;
    }

    if ((*in)->getBinder() != binder) {
        LOG(ERROR) << __func__ << ": parcel is associated with binder object " << binder
                   << " but called with " << (*in)->getBinder();
        return EX_ILLEGAL_STATE;
    }

    *out = new AParcel(binder);

    binder_status_t parcelStatus =
            binder->getBinder()->transact(code, *(*in)->operator->(), (*out)->operator->(), flags);

    if (parcelStatus != EX_NONE) {
        delete *out;
        *out = nullptr;
    }

    return parcelStatus;
}
