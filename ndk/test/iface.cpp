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

#include <android-base/logging.h>
#include <android/binder_manager.h>
#include <iface/iface.h>

using ::android::sp;
using ::android::wp;

const char* IFoo::kSomeInstanceName = "libbinder_ndk-test-IFoo";
const char* kIFooDescriptor = "my-special-IFoo-class";

struct IFoo_Class_Data {
    sp<IFoo> foo;
};

void* IFoo_Class_onCreate(void* args) {
    IFoo_Class_Data* foo = static_cast<IFoo_Class_Data*>(args);
    // This is a foo, but we're currently not verifying that. So, the method newLocalBinder is
    // coupled with this.
    return static_cast<void*>(foo);
}

void IFoo_Class_onDestroy(void* userData) {
    delete static_cast<IFoo_Class_Data*>(userData);
}

binder_status_t IFoo_Class_onTransact(AIBinder* binder, transaction_code_t code, const AParcel* in,
                                      AParcel* out) {
    binder_status_t stat = STATUS_FAILED_TRANSACTION;

    sp<IFoo> foo = static_cast<IFoo_Class_Data*>(AIBinder_getUserData(binder))->foo;
    CHECK(foo != nullptr) << "Transaction made on already deleted object";

    switch (code) {
        case IFoo::DOFOO: {
            int32_t valueIn;
            stat = AParcel_readInt32(in, &valueIn);
            if (stat != STATUS_OK) break;
            int32_t valueOut = foo->doubleNumber(valueIn);
            stat = AParcel_writeInt32(out, valueOut);
            break;
        }
    }

    return stat;
}

AIBinder_Class* IFoo::kClass = AIBinder_Class_define(kIFooDescriptor, IFoo_Class_onCreate,
                                                     IFoo_Class_onDestroy, IFoo_Class_onTransact);

class BpFoo : public IFoo {
public:
    BpFoo(AIBinder* binder) : mBinder(binder) {}
    virtual ~BpFoo() { AIBinder_decStrong(mBinder); }

    virtual int32_t doubleNumber(int32_t in) {
        AParcel* parcelIn;
        CHECK(STATUS_OK == AIBinder_prepareTransaction(mBinder, &parcelIn));

        CHECK(STATUS_OK == AParcel_writeInt32(parcelIn, in));

        AParcel* parcelOut;
        CHECK(STATUS_OK ==
              AIBinder_transact(mBinder, IFoo::DOFOO, &parcelIn, &parcelOut, 0 /*flags*/));

        int32_t out;
        CHECK(STATUS_OK == AParcel_readInt32(parcelOut, &out));

        AParcel_delete(parcelOut);

        return out;
    }

private:
    // Always assumes one refcount
    AIBinder* mBinder;
};

IFoo::~IFoo() {
    AIBinder_Weak_delete(mWeakBinder);
}

binder_status_t IFoo::addService(const char* instance) {
    AIBinder* binder = nullptr;

    if (mWeakBinder != nullptr) {
        // one strong ref count of binder
        binder = AIBinder_Weak_promote(mWeakBinder);
    }
    if (binder == nullptr) {
        // or one strong refcount here
        binder = AIBinder_new(IFoo::kClass, static_cast<void*>(new IFoo_Class_Data{this}));
        if (mWeakBinder != nullptr) {
            AIBinder_Weak_delete(mWeakBinder);
        }
        mWeakBinder = AIBinder_Weak_new(binder);
    }

    binder_status_t status = AServiceManager_addService(binder, instance);
    // Strong references we care about kept by remote process
    AIBinder_decStrong(binder);
    return status;
}

sp<IFoo> IFoo::getService(const char* instance) {
    AIBinder* binder = AServiceManager_getService(instance); // maybe nullptr
    if (binder == nullptr) {
        return nullptr;
    }

    if (!AIBinder_associateClass(binder, IFoo::kClass)) {
        AIBinder_decStrong(binder);
        return nullptr;
    }

    if (AIBinder_isRemote(binder)) {
        sp<IFoo> ret = new BpFoo(binder); // takes ownership of binder
        return ret;
    }

    IFoo_Class_Data* data = static_cast<IFoo_Class_Data*>(AIBinder_getUserData(binder));

    CHECK(data != nullptr); // always created with non-null data

    sp<IFoo> ret = data->foo;

    AIBinder* held = AIBinder_Weak_promote(ret->mWeakBinder);
    CHECK(held == binder);
    AIBinder_decStrong(held);

    // IFoo only keeps a weak reference to AIBinder, so we can drop this
    AIBinder_decStrong(binder);
    return ret;
}
