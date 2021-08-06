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
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>
#include <binder/RpcServer.h>
#include <binder/RpcSession.h>

#include <thread>

#include <signal.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <unistd.h>

using android::BBinder;
using android::defaultServiceManager;
using android::IBinder;
using android::interface_cast;
using android::IPCThreadState;
using android::IServiceManager;
using android::OK;
using android::ProcessState;
using android::RpcServer;
using android::RpcSession;
using android::sp;
using android::String16;
using android::binder::Status;

class MyBinderRpcBenchmark : public BnBinderRpcBenchmark {
    Status repeatString(const std::string& str, std::string* out) override {
        *out = str;
        return Status::ok();
    }
    Status repeatBinder(const sp<IBinder>& binder, sp<IBinder>* out) override {
        *out = binder;
        return Status::ok();
    }
    Status repeatBytes(const std::vector<uint8_t>& bytes, std::vector<uint8_t>* out) override {
        *out = bytes;
        return Status::ok();
    }
};

enum Transport {
    KERNEL,
    RPC,
};

static const std::initializer_list<int64_t> kTransportList = {
#ifdef __BIONIC__
        Transport::KERNEL,
#endif
        Transport::RPC};

static sp<RpcSession> gSession = RpcSession::make();
#ifdef __BIONIC__
static const String16 kKernelBinderInstance = String16(u"binderRpcBenchmark-control");
static sp<IBinder> gKernelBinder;
#endif

static sp<IBinder> getBinderForOptions(benchmark::State& state) {
    Transport transport = static_cast<Transport>(state.range(0));
    switch (transport) {
#ifdef __BIONIC__
        case KERNEL:
            return gKernelBinder;
#endif
        case RPC:
            return gSession->getRootObject();
        default:
            LOG(FATAL) << "Unknown transport value: " << transport;
            return nullptr;
    }
}

void BM_pingTransaction(benchmark::State& state) {
    sp<IBinder> binder = getBinderForOptions(state);

    while (state.KeepRunning()) {
        CHECK_EQ(OK, binder->pingBinder());
    }
}
BENCHMARK(BM_pingTransaction)->ArgsProduct({kTransportList});

void BM_repeatTwoPageString(benchmark::State& state) {
    sp<IBinder> binder = getBinderForOptions(state);

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
BENCHMARK(BM_repeatTwoPageString)->ArgsProduct({kTransportList});

void BM_throughputForTransportAndBytes(benchmark::State& state) {
    sp<IBinder> binder = getBinderForOptions(state);
    sp<IBinderRpcBenchmark> iface = interface_cast<IBinderRpcBenchmark>(binder);
    CHECK(iface != nullptr);

    std::vector<uint8_t> bytes = std::vector<uint8_t>(state.range(1));
    for (size_t i = 0; i < bytes.size(); i++) {
        bytes[i] = i % 256;
    }

    while (state.KeepRunning()) {
        std::vector<uint8_t> out;
        Status ret = iface->repeatBytes(bytes, &out);
        CHECK(ret.isOk()) << ret;
    }
}
BENCHMARK(BM_throughputForTransportAndBytes)
        ->ArgsProduct({kTransportList,
                       {64, 1024, 2048, 4096, 8182, 16364, 32728, 65535, 65536, 65537}});

void BM_repeatBinder(benchmark::State& state) {
    sp<IBinder> binder = gSession->getRootObject();
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
BENCHMARK(BM_repeatBinder)->ArgsProduct({kTransportList});

int main(int argc, char** argv) {
    ::benchmark::Initialize(&argc, argv);
    if (::benchmark::ReportUnrecognizedArguments(argc, argv)) return 1;

    std::string addr = std::string(getenv("TMPDIR") ?: "/tmp") + "/binderRpcBenchmark";
    (void)unlink(addr.c_str());

    std::cerr << "Tests suffixes:" << std::endl;
    std::cerr << "\t.../" << Transport::KERNEL << " is KERNEL" << std::endl;
    std::cerr << "\t.../" << Transport::RPC << " is RPC" << std::endl;

    if (0 == fork()) {
        prctl(PR_SET_PDEATHSIG, SIGHUP); // racey, okay
        sp<RpcServer> server = RpcServer::make();
        server->setRootObject(sp<MyBinderRpcBenchmark>::make());
        server->iUnderstandThisCodeIsExperimentalAndIWillNotUseItInProduction();
        CHECK(server->setupUnixDomainServer(addr.c_str()));
        server->join();
        exit(1);
    }

#ifdef __BIONIC__
    if (0 == fork()) {
        prctl(PR_SET_PDEATHSIG, SIGHUP); // racey, okay
        CHECK_EQ(OK,
                 defaultServiceManager()->addService(kKernelBinderInstance,
                                                     sp<MyBinderRpcBenchmark>::make()));
        IPCThreadState::self()->joinThreadPool();
        exit(1);
    }

    ProcessState::self()->setThreadPoolMaxThreadCount(1);
    ProcessState::self()->startThreadPool();

    gKernelBinder = defaultServiceManager()->waitForService(kKernelBinderInstance);
    CHECK_NE(nullptr, gKernelBinder.get());
#endif

    for (size_t tries = 0; tries < 5; tries++) {
        usleep(10000);
        if (gSession->setupUnixDomainClient(addr.c_str())) goto success;
    }
    LOG(FATAL) << "Could not connect.";
success:

    ::benchmark::RunSpecifiedBenchmarks();
    return 0;
}
