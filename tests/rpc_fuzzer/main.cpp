/*
 * Copyright (C) 2021 The Android Open Source Project
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
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <binder/Binder.h>
#include <binder/Parcel.h>
#include <binder/RpcServer.h>
#include <binder/RpcSession.h>
#include <fuzzer/FuzzedDataProvider.h>

#include <sys/resource.h>
#include <sys/un.h>

namespace android {

static const std::string kSock = std::string(getenv("TMPDIR") ?: "/tmp") +
        "/binderRpcFuzzerSocket_" + std::to_string(getpid());

class SomeBinder : public BBinder {
    status_t onTransact(uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags = 0) {
        (void)flags;

        if ((code & 1) == 0) {
            sp<IBinder> binder;
            (void)data.readStrongBinder(&binder);
            if (binder != nullptr) {
                (void)binder->pingBinder();
            }
        }
        if ((code & 2) == 0) {
            (void)data.readInt32();
        }
        if ((code & 4) == 0) {
            (void)reply->writeStrongBinder(sp<BBinder>::make());
        }

        return OK;
    }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > 50000) return 0;
    FuzzedDataProvider provider(data, size);

    unlink(kSock.c_str());

    sp<RpcServer> server = RpcServer::make();
    server->setRootObject(sp<SomeBinder>::make());
    server->iUnderstandThisCodeIsExperimentalAndIWillNotUseItInProduction();
    CHECK(server->setupUnixDomainServer(kSock.c_str()));

    std::thread serverThread([=] { (void)server->join(); });

    sockaddr_un addr{
            .sun_family = AF_UNIX,
    };
    CHECK_LT(kSock.size(), sizeof(addr.sun_path));
    memcpy(&addr.sun_path, kSock.c_str(), kSock.size());

    std::vector<base::unique_fd> connections;

    bool hangupBeforeShutdown = provider.ConsumeBool();

    while (provider.remaining_bytes() > 0) {
        if (connections.empty() || provider.ConsumeBool()) {
            base::unique_fd fd(TEMP_FAILURE_RETRY(socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)));
            CHECK_NE(fd.get(), -1);
            CHECK_EQ(0,
                     TEMP_FAILURE_RETRY(
                             connect(fd.get(), reinterpret_cast<sockaddr*>(&addr), sizeof(addr))))
                    << strerror(errno);
            connections.push_back(std::move(fd));
        } else {
            size_t idx = provider.ConsumeIntegralInRange<size_t>(0, connections.size() - 1);

            if (provider.ConsumeBool()) {
                std::vector<uint8_t> writeData = provider.ConsumeBytes<uint8_t>(
                        provider.ConsumeIntegralInRange<size_t>(0, provider.remaining_bytes()));
                CHECK(base::WriteFully(connections.at(idx).get(), writeData.data(),
                                       writeData.size()));
            } else {
                connections.erase(connections.begin() + idx); // hang up
            }
        }
    }

    if (hangupBeforeShutdown) {
        connections.clear();
        while (!server->listSessions().empty() && server->numUninitializedSessions()) {
            // wait for all threads to finish processing existing information
            usleep(1);
        }
    }

    while (!server->shutdown()) usleep(1);
    serverThread.join();

    return 0;
}

} // namespace android
