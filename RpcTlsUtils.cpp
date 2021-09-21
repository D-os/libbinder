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

#define LOG_TAG "RpcTlsUtils"
#include <log/log.h>

#include <binder/RpcTlsUtils.h>

#include "Utils.h"

namespace android {

namespace {

bssl::UniquePtr<X509> fromPem(const std::vector<uint8_t>& cert) {
    if (cert.size() > std::numeric_limits<int>::max()) return nullptr;
    bssl::UniquePtr<BIO> certBio(BIO_new_mem_buf(cert.data(), static_cast<int>(cert.size())));
    return bssl::UniquePtr<X509>(PEM_read_bio_X509(certBio.get(), nullptr, nullptr, nullptr));
}

bssl::UniquePtr<X509> fromDer(const std::vector<uint8_t>& cert) {
    if (cert.size() > std::numeric_limits<long>::max()) return nullptr;
    const unsigned char* data = cert.data();
    auto expectedEnd = data + cert.size();
    bssl::UniquePtr<X509> ret(d2i_X509(nullptr, &data, static_cast<long>(cert.size())));
    if (data != expectedEnd) {
        ALOGE("%s: %td bytes remaining!", __PRETTY_FUNCTION__, expectedEnd - data);
        return nullptr;
    }
    return ret;
}

} // namespace

bssl::UniquePtr<X509> deserializeCertificate(const std::vector<uint8_t>& cert,
                                             RpcCertificateFormat format) {
    switch (format) {
        case RpcCertificateFormat::PEM:
            return fromPem(cert);
        case RpcCertificateFormat::DER:
            return fromDer(cert);
    }
    LOG_ALWAYS_FATAL("Unsupported format %d", static_cast<int>(format));
}

std::vector<uint8_t> serializeCertificate(X509* x509, RpcCertificateFormat format) {
    bssl::UniquePtr<BIO> certBio(BIO_new(BIO_s_mem()));
    switch (format) {
        case RpcCertificateFormat::PEM: {
            TEST_AND_RETURN({}, PEM_write_bio_X509(certBio.get(), x509));
        } break;
        case RpcCertificateFormat::DER: {
            TEST_AND_RETURN({}, i2d_X509_bio(certBio.get(), x509));
        } break;
        default: {
            LOG_ALWAYS_FATAL("Unsupported format %d", static_cast<int>(format));
        }
    }
    const uint8_t* data;
    size_t len;
    TEST_AND_RETURN({}, BIO_mem_contents(certBio.get(), &data, &len));
    return std::vector<uint8_t>(data, data + len);
}

} // namespace android
