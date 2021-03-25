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

#include <memory>

#include <utils/Errors.h>

// WARNING: This is a feature which is still in development, and it is subject
// to radical change. Any production use of this may subject your code to any
// number of problems.

namespace android {

class Parcel;
struct RpcWireAddress;

/**
 * This class represents an identifier of a binder object.
 *
 * The purpose of this class it to hide the ABI of an RpcWireAddress, and
 * potentially allow us to change the size of it in the future (RpcWireAddress
 * is PIMPL, essentially - although the type that is used here is not exposed).
 */
class RpcAddress {
public:
    /**
     * The zero address is used for special RPC transactions, but it might also
     * be used in conjunction with readFromParcel.
     */
    static RpcAddress zero();

    bool isZero() const;

    /**
     * Create a new address which is unique
     */
    static RpcAddress unique();

    /**
     * Creates a new address as a copy of an embedded object.
     */
    static RpcAddress fromRawEmbedded(const RpcWireAddress* raw);
    const RpcWireAddress& viewRawEmbedded() const;

    bool operator<(const RpcAddress& rhs) const;
    std::string toString() const;

    status_t writeToParcel(Parcel* parcel) const;
    status_t readFromParcel(const Parcel& parcel);

    ~RpcAddress();

private:
    RpcAddress();

    std::shared_ptr<RpcWireAddress> mRawAddr;
};

} // namespace android
