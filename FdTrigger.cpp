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

#define LOG_TAG "FdTrigger"
#include <log/log.h>

#include <poll.h>

#include <android-base/macros.h>

#include "FdTrigger.h"
namespace android {

std::unique_ptr<FdTrigger> FdTrigger::make() {
    auto ret = std::make_unique<FdTrigger>();
    if (!android::base::Pipe(&ret->mRead, &ret->mWrite)) {
        ALOGE("Could not create pipe %s", strerror(errno));
        return nullptr;
    }
    return ret;
}

void FdTrigger::trigger() {
    mWrite.reset();
}

bool FdTrigger::isTriggered() {
    return mWrite == -1;
}

status_t FdTrigger::triggerablePoll(base::borrowed_fd fd, int16_t event) {
    while (true) {
        pollfd pfd[]{{.fd = fd.get(), .events = static_cast<int16_t>(event), .revents = 0},
                     {.fd = mRead.get(), .events = 0, .revents = 0}};
        int ret = TEMP_FAILURE_RETRY(poll(pfd, arraysize(pfd), -1));
        if (ret < 0) {
            return -errno;
        }
        if (ret == 0) {
            continue;
        }
        if (pfd[1].revents & POLLHUP) {
            return -ECANCELED;
        }
        return pfd[0].revents & event ? OK : DEAD_OBJECT;
    }
}

android::base::Result<bool> FdTrigger::isTriggeredPolled() {
    pollfd pfd{.fd = mRead.get(), .events = 0, .revents = 0};
    int ret = TEMP_FAILURE_RETRY(poll(&pfd, 1, 0));
    if (ret < 0) {
        return android::base::ErrnoError() << "FdTrigger::isTriggeredPolled: Error in poll()";
    }
    if (ret == 0) {
        return false;
    }
    if (pfd.revents & POLLHUP) {
        return true;
    }
    return android::base::Error() << "FdTrigger::isTriggeredPolled: poll() returns " << pfd.revents;
}

} // namespace android
