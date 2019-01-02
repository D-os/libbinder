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
 * @file binder_interface_utils.h
 * @brief This provides common C++ classes for common operations and as base classes for C++
 * interfaces.
 */

#pragma once

#include <android/binder_auto_utils.h>
#include <android/binder_ibinder.h>

#include <assert.h>

#include <memory>
#include <mutex>

namespace ndk {

/**
 * analog using std::shared_ptr for internally held refcount
 *
 * ref must be called at least one time during the lifetime of this object. The recommended way to
 * construct this object is with SharedRefBase::make.
 */
class SharedRefBase {
   public:
    SharedRefBase() {}
    virtual ~SharedRefBase() {
        std::call_once(mFlagThis, [&]() {
            __assert(__FILE__, __LINE__, "SharedRefBase: no ref created during lifetime");
        });
    }

    /**
     * A shared_ptr must be held to this object when this is called. This must be called once during
     * the lifetime of this object.
     */
    std::shared_ptr<SharedRefBase> ref() {
        std::shared_ptr<SharedRefBase> thiz = mThis.lock();

        std::call_once(mFlagThis, [&]() { mThis = thiz = std::shared_ptr<SharedRefBase>(this); });

        return thiz;
    }

    /**
     * Convenience method for a ref (see above) which automatically casts to the desired child type.
     */
    template <typename CHILD>
    std::shared_ptr<CHILD> ref() {
        return std::static_pointer_cast<CHILD>(ref());
    }

    /**
     * Convenience method for making an object directly with a reference.
     */
    template <class T, class... Args>
    static std::shared_ptr<T> make(Args&&... args) {
        T* t = new T(std::forward<Args>(args)...);
        return t->template ref<T>();
    }

   private:
    std::once_flag mFlagThis;
    std::weak_ptr<SharedRefBase> mThis;
};

/**
 * wrapper analog to IInterface
 */
class ICInterface : public SharedRefBase {
   public:
    ICInterface() {}
    virtual ~ICInterface() {}

    /**
     * This either returns the single existing implementation or creates a new implementation.
     */
    virtual SpAIBinder asBinder() = 0;

    /**
     * Returns whether this interface is in a remote process. If it cannot be determined locally,
     * this will be checked using AIBinder_isRemote.
     */
    virtual bool isRemote() = 0;
};

/**
 * implementation of IInterface for server (n = native)
 */
template <typename INTERFACE>
class BnCInterface : public INTERFACE {
   public:
    BnCInterface() {}
    virtual ~BnCInterface() {}

    SpAIBinder asBinder() override;

    bool isRemote() override { return true; }

   protected:
    /**
     * This function should only be called by asBinder. Otherwise, there is a possibility of
     * multiple AIBinder* objects being created for the same instance of an object.
     */
    virtual SpAIBinder createBinder() = 0;

   private:
    std::mutex mMutex;  // for asBinder
    ScopedAIBinder_Weak mWeakBinder;
};

/**
 * implementation of IInterface for client (p = proxy)
 */
template <typename INTERFACE>
class BpCInterface : public INTERFACE {
   public:
    explicit BpCInterface(const SpAIBinder& binder) : mBinder(binder) {}
    virtual ~BpCInterface() {}

    SpAIBinder asBinder() override;

    bool isRemote() override { return AIBinder_isRemote(mBinder.get()); }

   private:
    SpAIBinder mBinder;
};

template <typename INTERFACE>
SpAIBinder BnCInterface<INTERFACE>::asBinder() {
    std::lock_guard<std::mutex> l(mMutex);

    SpAIBinder binder;
    if (mWeakBinder.get() != nullptr) {
        binder.set(AIBinder_Weak_promote(mWeakBinder.get()));
    }
    if (binder.get() == nullptr) {
        binder = createBinder();
        mWeakBinder.set(AIBinder_Weak_new(binder.get()));
    }

    return binder;
}

template <typename INTERFACE>
SpAIBinder BpCInterface<INTERFACE>::asBinder() {
    return mBinder;
}

}  // namespace ndk

/** @} */
