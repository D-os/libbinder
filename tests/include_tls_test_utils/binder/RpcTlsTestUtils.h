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

#pragma once

#include <memory>
#include <mutex>
#include <vector>

#include <binder/RpcAuth.h>
#include <binder/RpcCertificateFormat.h>
#include <binder/RpcCertificateVerifier.h>
#include <binder/RpcTransport.h>
#include <openssl/ssl.h>
#include <utils/Errors.h>

namespace android {

constexpr const uint32_t kCertValidSeconds = 30 * (60 * 60 * 24); // 30 days
bssl::UniquePtr<EVP_PKEY> makeKeyPairForSelfSignedCert();
bssl::UniquePtr<X509> makeSelfSignedCert(EVP_PKEY* pKey, uint32_t validSeconds);

// An implementation of RpcAuth that generates a key pair and a self-signed
// certificate every time configure() is called.
class RpcAuthSelfSigned : public RpcAuth {
public:
    RpcAuthSelfSigned(uint32_t validSeconds = kCertValidSeconds) : mValidSeconds(validSeconds) {}
    status_t configure(SSL_CTX* ctx) override;

private:
    const uint32_t mValidSeconds;
};

class RpcAuthPreSigned : public RpcAuth {
public:
    RpcAuthPreSigned(bssl::UniquePtr<EVP_PKEY> pkey, bssl::UniquePtr<X509> cert)
          : mPkey(std::move(pkey)), mCert(std::move(cert)) {}
    status_t configure(SSL_CTX* ctx) override;

private:
    bssl::UniquePtr<EVP_PKEY> mPkey;
    bssl::UniquePtr<X509> mCert;
};

// A simple certificate verifier for testing.
// Keep a list of leaf certificates as trusted. No certificate chain support.
//
// All APIs are thread-safe. However, if verify() and addTrustedPeerCertificate() are called
// simultaneously in different threads, it is not deterministic whether verify() will use the
// certificate being added.
class RpcCertificateVerifierSimple : public RpcCertificateVerifier {
public:
    status_t verify(const SSL*, uint8_t*) override;

    // Add a trusted peer certificate. Peers presenting this certificate are accepted.
    //
    // Caller must ensure that RpcTransportCtx::newTransport() are called after all trusted peer
    // certificates are added. Otherwise, RpcTransport-s created before may not trust peer
    // certificates added later.
    [[nodiscard]] status_t addTrustedPeerCertificate(RpcCertificateFormat format,
                                                     const std::vector<uint8_t>& cert);

private:
    std::mutex mMutex; // for below
    std::vector<bssl::UniquePtr<X509>> mTrustedPeerCertificates;
};

// A RpcCertificateVerifier that does not verify anything.
class RpcCertificateVerifierNoOp : public RpcCertificateVerifier {
public:
    RpcCertificateVerifierNoOp(status_t status) : mStatus(status) {}
    status_t verify(const SSL*, uint8_t*) override { return mStatus; }

private:
    status_t mStatus;
};

} // namespace android
