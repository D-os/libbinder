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
#include <binder/RpcCertificateFormat.h>
#include <binder/RpcCertificateVerifier.h>
#include <binder/RpcServer.h>
#include <binder/RpcSession.h>
#include <binder/RpcTlsTestUtils.h>
#include <binder/RpcTlsUtils.h>
#include <binder/RpcTransportRaw.h>
#include <binder/RpcTransportTls.h>
#include <openssl/ssl.h>

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
using android::RpcAuthPreSigned;
using android::RpcCertificateFormat;
using android::RpcCertificateVerifier;
using android::RpcCertificateVerifierNoOp;
using android::RpcServer;
using android::RpcSession;
using android::RpcTransportCtxFactory;
using android::RpcTransportCtxFactoryRaw;
using android::RpcTransportCtxFactoryTls;
using android::sp;
using android::status_t;
using android::statusToString;
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
    RPC_TLS,
};

static const std::initializer_list<int64_t> kTransportList = {
#ifdef __BIONIC__
        Transport::KERNEL,
#endif
        Transport::RPC,
        Transport::RPC_TLS,
};

std::unique_ptr<RpcTransportCtxFactory> makeFactoryTls() {
    auto pkey = android::makeKeyPairForSelfSignedCert();
    CHECK_NE(pkey.get(), nullptr);
    auto cert = android::makeSelfSignedCert(pkey.get(), android::kCertValidSeconds);
    CHECK_NE(cert.get(), nullptr);

    auto verifier = std::make_shared<RpcCertificateVerifierNoOp>();
    auto auth = std::make_unique<RpcAuthPreSigned>(std::move(pkey), std::move(cert));
    return RpcTransportCtxFactoryTls::make(verifier, std::move(auth));
}

static sp<RpcSession> gSession = RpcSession::make();
// Certificate validation happens during handshake and does not affect the result of benchmarks.
// Skip certificate validation to simplify the setup process.
static sp<RpcSession> gSessionTls = RpcSession::make(makeFactoryTls());
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
        case RPC_TLS:
            return gSessionTls->getRootObject();
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
    sp<IBinder> binder = getBinderForOptions(state);
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

void forkRpcServer(const char* addr, const sp<RpcServer>& server) {
    if (0 == fork()) {
        prctl(PR_SET_PDEATHSIG, SIGHUP); // racey, okay
        server->setRootObject(sp<MyBinderRpcBenchmark>::make());
        server->iUnderstandThisCodeIsExperimentalAndIWillNotUseItInProduction();
        CHECK_EQ(OK, server->setupUnixDomainServer(addr));
        server->join();
        exit(1);
    }
}

void setupClient(const sp<RpcSession>& session, const char* addr) {
    status_t status;
    for (size_t tries = 0; tries < 5; tries++) {
        usleep(10000);
        status = session->setupUnixDomainClient(addr);
        if (status == OK) break;
    }
    CHECK_EQ(status, OK) << "Could not connect: " << addr << ": " << statusToString(status).c_str();
}

int main(int argc, char** argv) {
    ::benchmark::Initialize(&argc, argv);
    if (::benchmark::ReportUnrecognizedArguments(argc, argv)) return 1;

    std::cerr << "Tests suffixes:" << std::endl;
    std::cerr << "\t.../" << Transport::KERNEL << " is KERNEL" << std::endl;
    std::cerr << "\t.../" << Transport::RPC << " is RPC" << std::endl;
    std::cerr << "\t.../" << Transport::RPC_TLS << " is RPC with TLS" << std::endl;

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

    std::string tmp = getenv("TMPDIR") ?: "/tmp";

    std::string addr = tmp + "/binderRpcBenchmark";
    (void)unlink(addr.c_str());
    forkRpcServer(addr.c_str(), RpcServer::make(RpcTransportCtxFactoryRaw::make()));
    setupClient(gSession, addr.c_str());

    std::string tlsAddr = tmp + "/binderRpcTlsBenchmark";
    (void)unlink(tlsAddr.c_str());
    forkRpcServer(tlsAddr.c_str(), RpcServer::make(makeFactoryTls()));
    setupClient(gSessionTls, tlsAddr.c_str());

    ::benchmark::RunSpecifiedBenchmarks();
    return 0;
}
