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
#include <binder/RpcTlsTestUtils.h>
#include <binder/RpcTransport.h>
#include <binder/RpcTransportRaw.h>
#include <binder/RpcTransportTls.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

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

int passwordCallback(char* buf, int size, int /*rwflag*/, void* /*u*/) {
    constexpr const char pass[] = "xxxx"; // See create_certs.sh
    if (size <= 0) return 0;
    int numCopy = std::min<int>(size, sizeof(pass));
    (void)memcpy(buf, pass, numCopy);
    return numCopy;
}

struct ServerAuth {
    bssl::UniquePtr<EVP_PKEY> pkey;
    bssl::UniquePtr<X509> cert;
};

// Use pre-configured keys because runtime generated keys / certificates are not
// deterministic, and the algorithm is time consuming.
ServerAuth readServerKeyAndCert() {
    ServerAuth ret;

    auto keyPath = android::base::GetExecutableDirectory() + "/data/server.key";
    bssl::UniquePtr<BIO> keyBio(BIO_new_file(keyPath.c_str(), "r"));
    ret.pkey.reset(PEM_read_bio_PrivateKey(keyBio.get(), nullptr, passwordCallback, nullptr));
    CHECK_NE(ret.pkey.get(), nullptr);

    auto certPath = android::base::GetExecutableDirectory() + "/data/server.crt";
    bssl::UniquePtr<BIO> certBio(BIO_new_file(certPath.c_str(), "r"));
    ret.cert.reset(PEM_read_bio_X509(certBio.get(), nullptr, nullptr, nullptr));
    CHECK_NE(ret.cert.get(), nullptr);

    return ret;
}

std::unique_ptr<RpcAuth> createServerRpcAuth() {
    static auto sAuth = readServerKeyAndCert();

    CHECK(EVP_PKEY_up_ref(sAuth.pkey.get()));
    bssl::UniquePtr<EVP_PKEY> pkey(sAuth.pkey.get());
    CHECK(X509_up_ref(sAuth.cert.get()));
    bssl::UniquePtr<X509> cert(sAuth.cert.get());

    return std::make_unique<RpcAuthPreSigned>(std::move(pkey), std::move(cert));
}

std::unique_ptr<RpcTransportCtxFactory> makeTransportCtxFactory(FuzzedDataProvider* provider) {
    bool isTls = provider->ConsumeBool();
    if (!isTls) {
        return RpcTransportCtxFactoryRaw::make();
    }
    status_t verifyStatus = provider->ConsumeIntegral<status_t>();
    auto verifier = std::make_shared<RpcCertificateVerifierNoOp>(verifyStatus);
    return RpcTransportCtxFactoryTls::make(verifier, createServerRpcAuth());
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > 50000) return 0;
    FuzzedDataProvider provider(data, size);
    RAND_reset_for_fuzzing();

    unlink(kSock.c_str());

    sp<RpcServer> server = RpcServer::make(makeTransportCtxFactory(&provider));
    server->setRootObject(sp<SomeBinder>::make());
    CHECK_EQ(OK, server->setupUnixDomainServer(kSock.c_str()));

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
                std::string writeData = provider.ConsumeRandomLengthString();
                ssize_t size = TEMP_FAILURE_RETRY(send(connections.at(idx).get(), writeData.data(),
                                                       writeData.size(), MSG_NOSIGNAL));
                CHECK(errno == EPIPE || size == writeData.size())
                        << size << " " << writeData.size() << " " << strerror(errno);
            } else {
                connections.erase(connections.begin() + idx); // hang up
            }
        }
    }

    usleep(10000);

    if (hangupBeforeShutdown) {
        connections.clear();
        while (!server->listSessions().empty() || server->numUninitializedSessions()) {
            // wait for all threads to finish processing existing information
            usleep(1);
        }
    }

    while (!server->shutdown()) usleep(1);
    serverThread.join();

    return 0;
}

} // namespace android
