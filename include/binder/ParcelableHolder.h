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

#include <binder/Parcel.h>
#include <binder/Parcelable.h>
#include <mutex>
#include <optional>
#include <tuple>

namespace android {
namespace os {
/*
 * C++ implementation of the Java class android.os.ParcelableHolder
 */
class ParcelableHolder : public android::Parcelable {
public:
    ParcelableHolder() = delete;
    explicit ParcelableHolder(Stability stability) : mStability(stability){}
    virtual ~ParcelableHolder() = default;
    ParcelableHolder(const ParcelableHolder& other) {
        mParcelable = other.mParcelable;
        mParcelableName = other.mParcelableName;
        if (other.mParcelPtr) {
            mParcelPtr = std::make_unique<Parcel>();
            mParcelPtr->appendFrom(other.mParcelPtr.get(), 0, other.mParcelPtr->dataSize());
        }
        mStability = other.mStability;
    }

    status_t writeToParcel(Parcel* parcel) const override;
    status_t readFromParcel(const Parcel* parcel) override;

    void reset() {
        this->mParcelable = nullptr;
        this->mParcelableName = std::nullopt;
        this->mParcelPtr = nullptr;
    }

    template <typename T>
    bool setParcelable(T&& p) {
        using Tt = typename std::decay<T>::type;
        return setParcelable<Tt>(std::make_shared<Tt>(std::forward<T>(p)));
    }

    template <typename T>
    bool setParcelable(std::shared_ptr<T> p) {
        static_assert(std::is_base_of<Parcelable, T>::value, "T must be derived from Parcelable");
        if (p && this->getStability() > p->getStability()) {
            return false;
        }
        this->mParcelable = p;
        this->mParcelableName = T::getParcelableDescriptor();
        this->mParcelPtr = nullptr;
        return true;
    }

    template <typename T>
    std::shared_ptr<T> getParcelable() const {
        static_assert(std::is_base_of<Parcelable, T>::value, "T must be derived from Parcelable");
        const std::string& parcelableDesc = T::getParcelableDescriptor();
        if (!this->mParcelPtr) {
            if (!this->mParcelable || !this->mParcelableName) {
                ALOGD("empty ParcelableHolder");
                return nullptr;
            } else if (parcelableDesc != *mParcelableName) {
                ALOGD("extension class name mismatch expected:%s actual:%s",
                      mParcelableName->c_str(), parcelableDesc.c_str());
                return nullptr;
            }
            return std::shared_ptr<T>(mParcelable, reinterpret_cast<T*>(mParcelable.get()));
        }
        this->mParcelPtr->setDataPosition(0);
        status_t status = this->mParcelPtr->readUtf8FromUtf16(&this->mParcelableName);
        if (status != android::OK || parcelableDesc != this->mParcelableName) {
            this->mParcelableName = std::nullopt;
            return nullptr;
        }
        this->mParcelable = std::make_shared<T>();
        status = mParcelable.get()->readFromParcel(this->mParcelPtr.get());
        if (status != android::OK) {
            this->mParcelableName = std::nullopt;
            this->mParcelable = nullptr;
            return nullptr;
        }
        this->mParcelPtr = nullptr;
        return std::shared_ptr<T>(mParcelable, reinterpret_cast<T*>(mParcelable.get()));
    }

    Stability getStability() const override { return mStability; }

    inline bool operator!=(const ParcelableHolder& rhs) const {
        return this != &rhs;
    }
    inline bool operator<(const ParcelableHolder& rhs) const {
        return this < &rhs;
    }
    inline bool operator<=(const ParcelableHolder& rhs) const {
        return this <= &rhs;
    }
    inline bool operator==(const ParcelableHolder& rhs) const {
        return this == &rhs;
    }
    inline bool operator>(const ParcelableHolder& rhs) const {
        return this > &rhs;
    }
    inline bool operator>=(const ParcelableHolder& rhs) const {
        return this >= &rhs;
    }

private:
    mutable std::shared_ptr<Parcelable> mParcelable;
    mutable std::optional<std::string> mParcelableName;
    mutable std::unique_ptr<Parcel> mParcelPtr;
    Stability mStability;
};
} // namespace os
} // namespace android
