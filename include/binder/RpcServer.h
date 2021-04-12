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

#include <android-base/unique_fd.h>
#include <binder/IBinder.h>
#include <binder/RpcConnection.h>
#include <utils/Errors.h>
#include <utils/RefBase.h>

// WARNING: This is a feature which is still in development, and it is subject
// to radical change. Any production use of this may subject your code to any
// number of problems.

namespace android {

/**
 * This represents a server of an interface, which may be connected to by any
 * number of clients over sockets.
 *
 * This object is not (currently) thread safe. All calls to it are expected to
 * happen at process startup.
 */
class RpcServer final : public virtual RefBase {
public:
    static sp<RpcServer> make();

    void iUnderstandThisCodeIsExperimentalAndIWillNotUseItInProduction();

    /**
     * Setup a static connection, when the number of clients are known.
     *
     * Each call to this function corresponds to a different client, and clients
     * each have their own threadpools.
     *
     * TODO(b/167966510): support dynamic creation of connections/threads
     */
    sp<RpcConnection> addClientConnection();

    /**
     * Allowing a server to explicitly drop clients would be easy to add here,
     * but it is not currently implemented, since users of this functionality
     * could not use similar functionality if they are running under real
     * binder.
     */
    // void drop(const sp<RpcConnection>& connection);

    /**
     * The root object can be retrieved by any client, without any
     * authentication.
     */
    void setRootObject(const sp<IBinder>& binder);

    /**
     * Root object set with setRootObject
     */
    sp<IBinder> getRootObject();

    ~RpcServer();

private:
    friend sp<RpcServer>;
    RpcServer();

    bool mAgreedExperimental = false;

    sp<IBinder> mRootObject;

    std::vector<sp<RpcConnection>> mConnections; // per-client
};

} // namespace android
