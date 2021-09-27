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

#define LOG_TAG "RpcTlsTestUtils"
#include <log/log.h>

#include <binder/RpcTlsTestUtils.h>

#include <binder/RpcTlsUtils.h>

#include "../Utils.h" // for TEST_AND_RETURN

namespace android {

bssl::UniquePtr<EVP_PKEY> makeKeyPairForSelfSignedCert() {
    bssl::UniquePtr<EC_KEY> ec_key(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
    if (ec_key == nullptr || !EC_KEY_generate_key(ec_key.get())) {
        ALOGE("Failed to generate key pair.");
        return nullptr;
    }
    bssl::UniquePtr<EVP_PKEY> pkey(EVP_PKEY_new());
    // Use set1 instead of assign to avoid leaking ec_key when assign fails. set1 increments
    // the refcount of the ec_key, so it is okay to release it at the end of this function.
    if (pkey == nullptr || !EVP_PKEY_set1_EC_KEY(pkey.get(), ec_key.get())) {
        ALOGE("Failed to assign key pair.");
        return nullptr;
    }
    return pkey;
}

bssl::UniquePtr<X509> makeSelfSignedCert(EVP_PKEY* pkey, const uint32_t validSeconds) {
    bssl::UniquePtr<X509> x509(X509_new());
    bssl::UniquePtr<BIGNUM> serial(BN_new());
    bssl::UniquePtr<BIGNUM> serialLimit(BN_new());
    TEST_AND_RETURN(nullptr, BN_lshift(serialLimit.get(), BN_value_one(), 128));
    TEST_AND_RETURN(nullptr, BN_rand_range(serial.get(), serialLimit.get()));
    TEST_AND_RETURN(nullptr, BN_to_ASN1_INTEGER(serial.get(), X509_get_serialNumber(x509.get())));
    TEST_AND_RETURN(nullptr, X509_gmtime_adj(X509_getm_notBefore(x509.get()), 0));
    TEST_AND_RETURN(nullptr, X509_gmtime_adj(X509_getm_notAfter(x509.get()), validSeconds));

    X509_NAME* subject = X509_get_subject_name(x509.get());
    TEST_AND_RETURN(nullptr,
                    X509_NAME_add_entry_by_txt(subject, "O", MBSTRING_ASC,
                                               reinterpret_cast<const uint8_t*>("Android"), -1, -1,
                                               0));
    TEST_AND_RETURN(nullptr,
                    X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                                               reinterpret_cast<const uint8_t*>("BinderRPC"), -1,
                                               -1, 0));
    TEST_AND_RETURN(nullptr, X509_set_issuer_name(x509.get(), subject));

    TEST_AND_RETURN(nullptr, X509_set_pubkey(x509.get(), pkey));
    TEST_AND_RETURN(nullptr, X509_sign(x509.get(), pkey, EVP_sha256()));
    return x509;
}

status_t RpcAuthSelfSigned::configure(SSL_CTX* ctx) {
    auto pkey = makeKeyPairForSelfSignedCert();
    TEST_AND_RETURN(UNKNOWN_ERROR, pkey != nullptr);
    auto cert = makeSelfSignedCert(pkey.get(), mValidSeconds);
    TEST_AND_RETURN(UNKNOWN_ERROR, cert != nullptr);
    TEST_AND_RETURN(INVALID_OPERATION, SSL_CTX_use_PrivateKey(ctx, pkey.get()));
    TEST_AND_RETURN(INVALID_OPERATION, SSL_CTX_use_certificate(ctx, cert.get()));
    return OK;
}

status_t RpcAuthPreSigned::configure(SSL_CTX* ctx) {
    if (!SSL_CTX_use_PrivateKey(ctx, mPkey.get())) {
        return INVALID_OPERATION;
    }
    if (!SSL_CTX_use_certificate(ctx, mCert.get())) {
        return INVALID_OPERATION;
    }
    return OK;
}

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
