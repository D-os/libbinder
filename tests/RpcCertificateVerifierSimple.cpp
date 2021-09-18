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
#define LOG_TAG "RpcCertificateVerifierSimple"
#include <log/log.h>

#include <binder/RpcTlsUtils.h>

#include "RpcCertificateVerifierSimple.h"

namespace android {

status_t RpcCertificateVerifierSimple::verify(const SSL* ssl, uint8_t* outAlert) {
    const char* logPrefix = SSL_is_server(ssl) ? "Server" : "Client";
    bssl::UniquePtr<X509> peerCert(SSL_get_peer_certificate(ssl)); // Does not set error queue
    LOG_ALWAYS_FATAL_IF(peerCert == nullptr,
                        "%s: libssl should not ask to verify non-existing cert", logPrefix);

    std::lock_guard<std::mutex> lock(mMutex);
    for (const auto& trustedCert : mTrustedPeerCertificates) {
        if (0 == X509_cmp(trustedCert.get(), peerCert.get())) {
            return OK;
        }
    }
    *outAlert = SSL_AD_CERTIFICATE_UNKNOWN;
    return PERMISSION_DENIED;
}

status_t RpcCertificateVerifierSimple::addTrustedPeerCertificate(RpcCertificateFormat format,
                                                                 const std::vector<uint8_t>& cert) {
    bssl::UniquePtr<X509> x509 = deserializeCertificate(cert, format);
    if (x509 == nullptr) {
        ALOGE("Certificate is not in the proper format %s", PrintToString(format).c_str());
        return BAD_VALUE;
    }
    std::lock_guard<std::mutex> lock(mMutex);
    mTrustedPeerCertificates.push_back(std::move(x509));
    return OK;
}

} // namespace android
