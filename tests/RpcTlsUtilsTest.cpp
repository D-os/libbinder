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

#include <binder/RpcTlsTestUtils.h>
#include <binder/RpcTlsUtils.h>
#include <gtest/gtest.h>

namespace android {

std::string toDebugString(EVP_PKEY* pkey) {
    bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
    int res = EVP_PKEY_print_public(bio.get(), pkey, 2, nullptr);
    std::string buf = "\nEVP_PKEY_print_public -> " + std::to_string(res) + "\n";
    if (BIO_write(bio.get(), buf.data(), buf.length()) <= 0) return {};
    res = EVP_PKEY_print_private(bio.get(), pkey, 2, nullptr);
    buf = "\nEVP_PKEY_print_private -> " + std::to_string(res);
    if (BIO_write(bio.get(), buf.data(), buf.length()) <= 0) return {};
    const uint8_t* data;
    size_t len;
    if (!BIO_mem_contents(bio.get(), &data, &len)) return {};
    return std::string(reinterpret_cast<const char*>(data), len);
}

class RpcTlsUtilsKeyTest : public testing::TestWithParam<RpcKeyFormat> {
public:
    static inline std::string PrintParamInfo(const testing::TestParamInfo<ParamType>& info) {
        return PrintToString(info.param);
    }
};

TEST_P(RpcTlsUtilsKeyTest, Test) {
    auto pkey = makeKeyPairForSelfSignedCert();
    ASSERT_NE(nullptr, pkey);
    auto pkeyData = serializeUnencryptedPrivatekey(pkey.get(), GetParam());
    auto deserializedPkey = deserializeUnencryptedPrivatekey(pkeyData, GetParam());
    ASSERT_NE(nullptr, deserializedPkey);
    EXPECT_EQ(1, EVP_PKEY_cmp(pkey.get(), deserializedPkey.get()))
            << "expected: " << toDebugString(pkey.get())
            << "\nactual: " << toDebugString(deserializedPkey.get());
}

INSTANTIATE_TEST_CASE_P(RpcTlsUtilsTest, RpcTlsUtilsKeyTest,
                        testing::Values(RpcKeyFormat::PEM, RpcKeyFormat::DER),
                        RpcTlsUtilsKeyTest::PrintParamInfo);

class RpcTlsUtilsCertTest : public testing::TestWithParam<RpcCertificateFormat> {
public:
    static inline std::string PrintParamInfo(const testing::TestParamInfo<ParamType>& info) {
        return PrintToString(info.param);
    }
};

TEST_P(RpcTlsUtilsCertTest, Test) {
    auto pkey = makeKeyPairForSelfSignedCert();
    ASSERT_NE(nullptr, pkey);
    // Make certificate from the original key in memory
    auto cert = makeSelfSignedCert(pkey.get(), kCertValidSeconds);
    ASSERT_NE(nullptr, cert);
    auto certData = serializeCertificate(cert.get(), GetParam());
    auto deserializedCert = deserializeCertificate(certData, GetParam());
    ASSERT_NE(nullptr, deserializedCert);
    EXPECT_EQ(0, X509_cmp(cert.get(), deserializedCert.get()));
}

INSTANTIATE_TEST_CASE_P(RpcTlsUtilsTest, RpcTlsUtilsCertTest,
                        testing::Values(RpcCertificateFormat::PEM, RpcCertificateFormat::DER),
                        RpcTlsUtilsCertTest::PrintParamInfo);

class RpcTlsUtilsKeyAndCertTest
      : public testing::TestWithParam<std::tuple<RpcKeyFormat, RpcCertificateFormat>> {
public:
    static inline std::string PrintParamInfo(const testing::TestParamInfo<ParamType>& info) {
        auto [keyFormat, certificateFormat] = info.param;
        return "key_" + PrintToString(keyFormat) + "_cert_" + PrintToString(certificateFormat);
    }
};

TEST_P(RpcTlsUtilsKeyAndCertTest, TestCertFromDeserializedKey) {
    auto [keyFormat, certificateFormat] = GetParam();
    auto pkey = makeKeyPairForSelfSignedCert();
    ASSERT_NE(nullptr, pkey);
    auto pkeyData = serializeUnencryptedPrivatekey(pkey.get(), keyFormat);
    auto deserializedPkey = deserializeUnencryptedPrivatekey(pkeyData, keyFormat);
    ASSERT_NE(nullptr, deserializedPkey);

    // Make certificate from deserialized key loaded from bytes
    auto cert = makeSelfSignedCert(deserializedPkey.get(), kCertValidSeconds);
    ASSERT_NE(nullptr, cert);
    auto certData = serializeCertificate(cert.get(), certificateFormat);
    auto deserializedCert = deserializeCertificate(certData, certificateFormat);
    ASSERT_NE(nullptr, deserializedCert);
    EXPECT_EQ(0, X509_cmp(cert.get(), deserializedCert.get()));
}

INSTANTIATE_TEST_CASE_P(RpcTlsUtilsTest, RpcTlsUtilsKeyAndCertTest,
                        testing::Combine(testing::Values(RpcKeyFormat::PEM, RpcKeyFormat::DER),
                                         testing::Values(RpcCertificateFormat::PEM,
                                                         RpcCertificateFormat::DER)),
                        RpcTlsUtilsKeyAndCertTest::PrintParamInfo);

} // namespace android
