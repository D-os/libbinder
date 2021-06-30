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

#include <sysexits.h>

#include <android-base/logging.h>
#include <binder/IBinder.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>

namespace {
class Service : public android::BBinder {
public:
    Service(std::string_view descriptor) : mDescriptor(descriptor.data(), descriptor.size()) {}
    const android::String16& getInterfaceDescriptor() const override { return mDescriptor; }

private:
    android::String16 mDescriptor;
};
} // namespace

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "usage: " << argv[0] << " <service-name> <interface-descriptor>" << std::endl;
        return EX_USAGE;
    }
    auto name = argv[1];
    auto descriptor = argv[2];

    auto sm = android::defaultServiceManager();
    CHECK(sm != nullptr);
    auto service = android::sp<Service>::make(descriptor);
    auto status = sm->addService(android::String16(name), service);
    CHECK_EQ(android::OK, status) << android::statusToString(status);
    std::cout << "running..." << std::endl;
    android::ProcessState::self()->startThreadPool();
    android::IPCThreadState::self()->joinThreadPool();
    LOG(ERROR) << "joinThreadPool exits";
    return EX_SOFTWARE;
}
