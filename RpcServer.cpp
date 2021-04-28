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

#define LOG_TAG "RpcServer"

#include <sys/socket.h>
#include <sys/un.h>

#include <thread>
#include <vector>

#include <binder/Parcel.h>
#include <binder/RpcServer.h>
#include <log/log.h>
#include "RpcState.h"

#include "RpcWireFormat.h"

namespace android {

RpcServer::RpcServer() {}
RpcServer::~RpcServer() {}

sp<RpcServer> RpcServer::make() {
    return sp<RpcServer>::make();
}

void RpcServer::iUnderstandThisCodeIsExperimentalAndIWillNotUseItInProduction() {
    mAgreedExperimental = true;
}

void RpcServer::setMaxThreads(size_t threads) {
    LOG_ALWAYS_FATAL_IF(threads <= 0, "RpcServer is useless without threads");
    {
        // this lock should only ever be needed in the error case
        std::lock_guard<std::mutex> _l(mLock);
        LOG_ALWAYS_FATAL_IF(mConnections.size() > 0,
                            "Must specify max threads before creating a connection");
    }
    mMaxThreads = threads;
}

size_t RpcServer::getMaxThreads() {
    return mMaxThreads;
}

void RpcServer::setRootObject(const sp<IBinder>& binder) {
    std::lock_guard<std::mutex> _l(mLock);
    mRootObject = binder;
}

sp<IBinder> RpcServer::getRootObject() {
    std::lock_guard<std::mutex> _l(mLock);
    return mRootObject;
}

sp<RpcConnection> RpcServer::addClientConnection() {
    LOG_ALWAYS_FATAL_IF(!mAgreedExperimental, "no!");

    auto connection = RpcConnection::make();
    connection->setForServer(sp<RpcServer>::fromExisting(this));
    {
        std::lock_guard<std::mutex> _l(mLock);
        LOG_ALWAYS_FATAL_IF(mStarted,
                            "currently only supports adding client connections at creation time");
        mConnections.push_back(connection);
    }
    return connection;
}

void RpcServer::join() {
    std::vector<std::thread> pool;
    {
        std::lock_guard<std::mutex> _l(mLock);
        mStarted = true;
        for (const sp<RpcConnection>& connection : mConnections) {
            for (size_t i = 0; i < mMaxThreads; i++) {
                pool.push_back(std::thread([=] { connection->join(); }));
            }
        }
    }

    // TODO(b/185167543): don't waste extra thread for join, and combine threads
    // between clients
    for (auto& t : pool) t.join();
}

} // namespace android
