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

#include <openssl/ssl.h>
#include <utils/Errors.h>

namespace android {

// An interface with a function that verifies a peer certificate. It is a wrapper over the custom
// verify function (see SSL_CTX_set_custom_verify).
class RpcCertificateVerifier {
public:
    virtual ~RpcCertificateVerifier() = default;
    virtual status_t verify(const X509* peerCert, uint8_t* outAlert) = 0;
};

} // namespace android
