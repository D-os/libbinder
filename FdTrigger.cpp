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

#include "FdTrigger.h"

#include <poll.h>

#include <android-base/macros.h>

#include "RpcState.h"
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
    LOG_ALWAYS_FATAL_IF(event == 0, "triggerablePoll %d with event 0 is not allowed", fd.get());
    pollfd pfd[]{{.fd = fd.get(), .events = static_cast<int16_t>(event), .revents = 0},
                 {.fd = mRead.get(), .events = 0, .revents = 0}};
    int ret = TEMP_FAILURE_RETRY(poll(pfd, arraysize(pfd), -1));
    if (ret < 0) {
        return -errno;
    }
    LOG_ALWAYS_FATAL_IF(ret == 0, "poll(%d) returns 0 with infinite timeout", fd.get());

    // At least one FD has events. Check them.

    // Detect explicit trigger(): DEAD_OBJECT
    if (pfd[1].revents & POLLHUP) {
        return DEAD_OBJECT;
    }
    // See unknown flags in trigger FD's revents (POLLERR / POLLNVAL).
    // Treat this error condition as UNKNOWN_ERROR.
    if (pfd[1].revents != 0) {
        ALOGE("Unknown revents on trigger FD %d: revents = %d", pfd[1].fd, pfd[1].revents);
        return UNKNOWN_ERROR;
    }

    // pfd[1].revents is 0, hence pfd[0].revents must be set, and only possible values are
    // a subset of event | POLLHUP | POLLERR | POLLNVAL.

    // POLLNVAL: invalid FD number, e.g. not opened.
    if (pfd[0].revents & POLLNVAL) {
        return BAD_VALUE;
    }

    // Error condition. It wouldn't be possible to do I/O on |fd| afterwards.
    // Note: If this is the write end of a pipe then POLLHUP may also be set simultaneously. We
    //   still want DEAD_OBJECT in this case.
    if (pfd[0].revents & POLLERR) {
        LOG_RPC_DETAIL("poll() incoming FD %d results in revents = %d", pfd[0].fd, pfd[0].revents);
        return DEAD_OBJECT;
    }

    // Success condition; event flag(s) set. Even though POLLHUP may also be set,
    // treat it as a success condition to ensure data is drained.
    if (pfd[0].revents & event) {
        return OK;
    }

    // POLLHUP: Peer closed connection. Treat as DEAD_OBJECT.
    // This is a very common case, so don't log.
    return DEAD_OBJECT;
}

} // namespace android
