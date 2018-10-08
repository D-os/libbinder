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
 * @file binder_auto_utils.h
 * @brief These objects provide a more C++-like thin interface to the .
 */

#pragma once

#include <android/binder_ibinder.h>
#include <android/binder_parcel.h>
#include <android/binder_status.h>

#ifdef __cplusplus

#include <cstddef>

namespace android {

/**
 * Represents one strong pointer to an AIBinder object.
 */
class AutoAIBinder {
public:
    /**
     * Takes ownership of one strong refcount of binder.
     */
    explicit AutoAIBinder(AIBinder* binder = nullptr) : mBinder(binder) {}

    /**
     * Convenience operator for implicitly constructing an AutoAIBinder from nullptr. This is not
     * explicit because it is not taking ownership of anything.
     */
    AutoAIBinder(std::nullptr_t) : AutoAIBinder() {}

    /**
     * This will delete the underlying object if it exists. See operator=.
     */
    AutoAIBinder(const AutoAIBinder& other) { *this = other; }

    /**
     * This deletes the underlying object if it exists. See set.
     */
    ~AutoAIBinder() { set(nullptr); }

    /**
     * This takes ownership of a binder from another AIBinder object but it does not affect the
     * ownership of that other object.
     */
    AutoAIBinder& operator=(const AutoAIBinder& other) {
        AIBinder_incStrong(other.mBinder);
        set(other.mBinder);
        return *this;
    }

    /**
     * Takes ownership of one strong refcount of binder
     */
    void set(AIBinder* binder) {
        if (mBinder != nullptr) AIBinder_decStrong(mBinder);
        mBinder = binder;
    }

    /**
     * This returns the underlying binder object for transactions. If it is used to create another
     * AutoAIBinder object, it should first be incremented.
     */
    AIBinder* get() const { return mBinder; }

    /**
     * This allows the value in this class to be set from beneath it. If you call this method and
     * then change the value of T*, you must take ownership of the value you are replacing and add
     * ownership to the object that is put in here.
     *
     * Recommended use is like this:
     *   AutoAIBinder a;  // will be nullptr
     *   SomeInitFunction(a.getR());  // value is initialized with refcount
     *
     * Other usecases are discouraged.
     *
     */
    AIBinder** getR() { return &mBinder; }

private:
    AIBinder* mBinder = nullptr;
};

/**
 * This baseclass owns a single object, used to make various classes RAII.
 */
template <typename T, void (*Destroy)(T*)>
class AutoA {
public:
    /**
     * Takes ownership of t.
     */
    explicit AutoA(T* t = nullptr) : mT(t) {}

    /**
     * This deletes the underlying object if it exists. See set.
     */
    ~AutoA() { set(nullptr); }

    /**
     * Takes ownership of t.
     */
    void set(T* t) {
        Destroy(mT);
        mT = t;
    }

    /**
     * This returns the underlying object to be modified but does not affect ownership.
     */
    T* get() { return mT; }

    /**
     * This returns the const underlying object but does not affect ownership.
     */
    const T* get() const { return mT; }

    /**
     * This allows the value in this class to be set from beneath it. If you call this method and
     * then change the value of T*, you must take ownership of the value you are replacing and add
     * ownership to the object that is put in here.
     *
     * Recommended use is like this:
     *   AutoA<T> a; // will be nullptr
     *   SomeInitFunction(a.getR()); // value is initialized with refcount
     *
     * Other usecases are discouraged.
     *
     */
    T** getR() { return &mT; }

    // copy-constructing, or move/copy assignment is disallowed
    AutoA(const AutoA&) = delete;
    AutoA& operator=(const AutoA&) = delete;
    AutoA& operator=(AutoA&&) = delete;

    // move-constructing is okay
    AutoA(AutoA&&) = default;

private:
    T* mT;
};

/**
 * Convenience wrapper. See AParcel.
 */
class AutoAParcel : public AutoA<AParcel, AParcel_delete> {
public:
    /**
     * Takes ownership of a.
     */
    explicit AutoAParcel(AParcel* a = nullptr) : AutoA(a) {}
    ~AutoAParcel() {}
    AutoAParcel(AutoAParcel&&) = default;
};

/**
 * Convenience wrapper. See AStatus.
 */
class AutoAStatus : public AutoA<AStatus, AStatus_delete> {
public:
    /**
     * Takes ownership of a.
     */
    explicit AutoAStatus(AStatus* a = nullptr) : AutoA(a) {}
    ~AutoAStatus() {}
    AutoAStatus(AutoAStatus&&) = default;

    /**
     * See AStatus_isOk.
     */
    bool isOk() { return get() != nullptr && AStatus_isOk(get()); }
};

/**
 * Convenience wrapper. See AIBinder_DeathRecipient.
 */
class AutoAIBinder_DeathRecipient
      : public AutoA<AIBinder_DeathRecipient, AIBinder_DeathRecipient_delete> {
public:
    /**
     * Takes ownership of a.
     */
    explicit AutoAIBinder_DeathRecipient(AIBinder_DeathRecipient* a = nullptr) : AutoA(a) {}
    ~AutoAIBinder_DeathRecipient() {}
    AutoAIBinder_DeathRecipient(AutoAIBinder_DeathRecipient&&) = default;
};

/**
 * Convenience wrapper. See AIBinder_Weak.
 */
class AutoAIBinder_Weak : public AutoA<AIBinder_Weak, AIBinder_Weak_delete> {
public:
    /**
     * Takes ownership of a.
     */
    explicit AutoAIBinder_Weak(AIBinder_Weak* a = nullptr) : AutoA(a) {}
    ~AutoAIBinder_Weak() {}
    AutoAIBinder_Weak(AutoAIBinder_Weak&&) = default;

    /**
     * See AIBinder_Weak_promote.
     */
    AutoAIBinder promote() { return AutoAIBinder(AIBinder_Weak_promote(get())); }
};

} // namespace android

#endif // __cplusplus

/** @} */
