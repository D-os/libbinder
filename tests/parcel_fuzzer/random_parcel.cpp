/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <fuzzbinder/random_parcel.h>

#include <android-base/logging.h>
#include <binder/IServiceManager.h>
#include <fuzzbinder/random_fd.h>
#include <utils/String16.h>

namespace android {

class NamedBinder : public BBinder {
public:
    NamedBinder(const String16& descriptor) : mDescriptor(descriptor) {}
    const String16& getInterfaceDescriptor() const override { return mDescriptor; }

private:
    String16 mDescriptor;
};

void fillRandomParcel(Parcel* p, FuzzedDataProvider&& provider) {
    while (provider.remaining_bytes() > 0) {
        auto fillFunc = provider.PickValueInArray<const std::function<void()>>({
                // write data
                [&]() {
                    size_t toWrite =
                            provider.ConsumeIntegralInRange<size_t>(0, provider.remaining_bytes());
                    std::vector<uint8_t> data = provider.ConsumeBytes<uint8_t>(toWrite);
                    CHECK(OK == p->write(data.data(), data.size()));
                },
                // write FD
                [&]() {
                    int fd = getRandomFd(&provider);
                    CHECK(OK == p->writeFileDescriptor(fd, true /*takeOwnership*/));
                },
                // write binder
                [&]() {
                    auto makeFunc = provider.PickValueInArray<const std::function<sp<IBinder>()>>({
                            [&]() {
                                // descriptor is the length of a class name, e.g.
                                // "some.package.Foo"
                                std::string str =
                                        provider.ConsumeRandomLengthString(100 /*max length*/);
                                return new NamedBinder(String16(str.c_str()));
                            },
                            []() {
                                // this is the easiest remote binder to get ahold of, and it
                                // should be able to handle anything thrown at it, and
                                // essentially every process can talk to it, so it's a good
                                // candidate for checking usage of an actual BpBinder
                                return IInterface::asBinder(defaultServiceManager());
                            },
                            []() { return nullptr; },
                    });
                    sp<IBinder> binder = makeFunc();
                    CHECK(OK == p->writeStrongBinder(binder));
                },
        });

        fillFunc();
    }
}

} // namespace android
