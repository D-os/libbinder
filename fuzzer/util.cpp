/*
 * Copyright (C) 2019 The Android Open Source Project
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
#define FUZZ_LOG_TAG "util"
#include "util.h"

#include <android-base/logging.h>

#include <iomanip>
#include <sstream>

std::string hexString(const void* bytes, size_t len) {
    if (bytes == nullptr) return "<null>";

    std::ostringstream s;
    s << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; i++) {
        s << std::setw(2) << static_cast<int>(
            static_cast<const uint8_t*>(bytes)[i]);
    }
    return s.str();
}
std::string hexString(const std::vector<uint8_t>& bytes) {
    return hexString(bytes.data(), bytes.size());
}
