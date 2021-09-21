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

#include <binder/RpcAuth.h>

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

} // namespace android
