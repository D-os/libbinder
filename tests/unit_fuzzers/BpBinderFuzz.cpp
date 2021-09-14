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

#include <BpBinderFuzzFunctions.h>
#include <IBinderFuzzFunctions.h>
#include <commonFuzzHelpers.h>
#include <fuzzer/FuzzedDataProvider.h>

#include <android-base/logging.h>
#include <binder/BpBinder.h>
#include <binder/IServiceManager.h>
#include <binder/RpcServer.h>
#include <binder/RpcSession.h>

#include <signal.h>
#include <sys/prctl.h>
#include <thread>

namespace android {

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    std::string addr = std::string(getenv("TMPDIR") ?: "/tmp") + "/binderRpcBenchmark";
    (void)unlink(addr.c_str());

    sp<RpcServer> server = RpcServer::make();

    // use RPC binder because fuzzer can't get coverage from another process.
    auto thread = std::thread([&]() {
        prctl(PR_SET_PDEATHSIG, SIGHUP); // racey, okay
        server->setRootObject(sp<BBinder>::make());
        server->iUnderstandThisCodeIsExperimentalAndIWillNotUseItInProduction();
        CHECK_EQ(OK, server->setupUnixDomainServer(addr.c_str()));
        server->join();
    });

    sp<RpcSession> session = RpcSession::make();
    status_t status;
    for (size_t tries = 0; tries < 5; tries++) {
        usleep(10000);
        status = session->setupUnixDomainClient(addr.c_str());
        if (status == OK) break;
    }
    CHECK_EQ(status, OK) << "Unable to connect";

    sp<BpBinder> bpBinder = session->getRootObject()->remoteBinder();

    // To prevent memory from running out from calling too many add item operations.
    const uint32_t MAX_RUNS = 2048;
    uint32_t count = 0;
    sp<IBinder::DeathRecipient> s_recipient = new FuzzDeathRecipient();

    while (fdp.remaining_bytes() > 0 && count++ < MAX_RUNS) {
        if (fdp.ConsumeBool()) {
            callArbitraryFunction(&fdp, gBPBinderOperations, bpBinder, s_recipient);
        } else {
            callArbitraryFunction(&fdp, gIBinderOperations, bpBinder.get());
        }
    }

    CHECK(session->shutdownAndWait(true)) << "couldn't shutdown session";
    CHECK(server->shutdown()) << "couldn't shutdown server";
    thread.join();

    return 0;
}
} // namespace android
