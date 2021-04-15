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

#include <BnBinderRpcBenchmark.h>
#include <android-base/logging.h>
#include <benchmark/benchmark.h>
#include <binder/Binder.h>
#include <binder/RpcConnection.h>
#include <binder/RpcServer.h>

#include <thread>

#include <sys/types.h>
#include <unistd.h>

using android::BBinder;
using android::IBinder;
using android::interface_cast;
using android::OK;
using android::RpcConnection;
using android::RpcServer;
using android::sp;
using android::binder::Status;

class MyBinderRpcBenchmark : public BnBinderRpcBenchmark {
    Status repeatString(const std::string& str, std::string* out) override {
        *out = str;
        return Status::ok();
    }
    Status repeatBinder(const sp<IBinder>& str, sp<IBinder>* out) override {
        *out = str;
        return Status::ok();
    }
};

static sp<RpcConnection> gConnection = RpcConnection::make();

void BM_getRootObject(benchmark::State& state) {
    while (state.KeepRunning()) {
        CHECK(gConnection->getRootObject() != nullptr);
    }
}
BENCHMARK(BM_getRootObject);

void BM_pingTransaction(benchmark::State& state) {
    sp<IBinder> binder = gConnection->getRootObject();
    CHECK(binder != nullptr);

    while (state.KeepRunning()) {
        CHECK_EQ(OK, binder->pingBinder());
    }
}
BENCHMARK(BM_pingTransaction);

void BM_repeatString(benchmark::State& state) {
    sp<IBinder> binder = gConnection->getRootObject();
    CHECK(binder != nullptr);
    sp<IBinderRpcBenchmark> iface = interface_cast<IBinderRpcBenchmark>(binder);
    CHECK(iface != nullptr);

    // Googlers might see go/another-look-at-aidl-hidl-perf
    //
    // When I checked in July 2019, 99.5% of AIDL transactions and 99.99% of HIDL
    // transactions were less than one page in size (system wide during a test
    // involving media and camera). This is why this diverges from
    // binderThroughputTest and hwbinderThroughputTest. Future consideration - get
    // this data on continuous integration. Here we are testing sending a
    // transaction of twice this size. In other cases, we should focus on
    // benchmarks of particular usecases. If individual binder transactions like
    // the ones tested here are fast, then Android performance will be dominated
    // by how many binder calls work together (and by factors like the scheduler,
    // thermal throttling, core choice, etc..).
    std::string str = std::string(getpagesize() * 2, 'a');
    CHECK_EQ(str.size(), getpagesize() * 2);

    while (state.KeepRunning()) {
        std::string out;
        Status ret = iface->repeatString(str, &out);
        CHECK(ret.isOk()) << ret;
    }
}
BENCHMARK(BM_repeatString);

void BM_repeatBinder(benchmark::State& state) {
    sp<IBinder> binder = gConnection->getRootObject();
    CHECK(binder != nullptr);
    sp<IBinderRpcBenchmark> iface = interface_cast<IBinderRpcBenchmark>(binder);
    CHECK(iface != nullptr);

    while (state.KeepRunning()) {
        // force creation of a new address
        sp<IBinder> binder = sp<BBinder>::make();

        sp<IBinder> out;
        Status ret = iface->repeatBinder(binder, &out);
        CHECK(ret.isOk()) << ret;
    }
}
BENCHMARK(BM_repeatBinder);

int main(int argc, char** argv) {
    ::benchmark::Initialize(&argc, argv);
    if (::benchmark::ReportUnrecognizedArguments(argc, argv)) return 1;

    std::string addr = std::string(getenv("TMPDIR") ?: "/tmp") + "/binderRpcBenchmark";
    (void)unlink(addr.c_str());

    std::thread([addr]() {
        sp<RpcServer> server = RpcServer::make();
        server->setRootObject(sp<MyBinderRpcBenchmark>::make());

        server->iUnderstandThisCodeIsExperimentalAndIWillNotUseItInProduction();

        sp<RpcConnection> connection = server->addClientConnection();
        CHECK(connection->setupUnixDomainServer(addr.c_str()));

        connection->join();
    }).detach();

    for (size_t tries = 0; tries < 5; tries++) {
        usleep(10000);
        if (gConnection->addUnixDomainClient(addr.c_str())) goto success;
    }
    LOG(FATAL) << "Could not connect.";
success:

    ::benchmark::RunSpecifiedBenchmarks();
}
