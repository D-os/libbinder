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

sp<RpcConnection> RpcServer::addClientConnection() {
    LOG_ALWAYS_FATAL_IF(!mAgreedExperimental, "no!");

    auto connection = RpcConnection::make();
    connection->setForServer(sp<RpcServer>::fromExisting(this));
    mConnections.push_back(connection);
    return connection;
}

void RpcServer::setRootObject(const sp<IBinder>& binder) {
    LOG_ALWAYS_FATAL_IF(mRootObject != nullptr, "There can only be one root object");
    mRootObject = binder;
}

sp<IBinder> RpcServer::getRootObject() {
    return mRootObject;
}

} // namespace android
