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

#include <memory>

#include <android-base/result.h>
#include <android-base/unique_fd.h>
#include <utils/Errors.h>

namespace android {

/** This is not a pipe. */
class FdTrigger {
public:
    /** Returns nullptr for error case */
    static std::unique_ptr<FdTrigger> make();

    /**
     * Close the write end of the pipe so that the read end receives POLLHUP.
     * Not threadsafe.
     */
    void trigger();

    /**
     * Check whether this has been triggered by checking the write end.
     */
    [[nodiscard]] bool isTriggered();

    /**
     * Poll for a read event.
     *
     * event - for pollfd
     *
     * Return:
     *   true - time to read!
     *   false - trigger happened
     */
    [[nodiscard]] status_t triggerablePoll(base::borrowed_fd fd, int16_t event);

    /**
     * Check whether this has been triggered by poll()ing the read end.
     *
     * Return:
     *   true - triggered
     *   false - not triggered
     *   error - error when polling
     */
    [[nodiscard]] android::base::Result<bool> isTriggeredPolled();

private:
    base::unique_fd mWrite;
    base::unique_fd mRead;
};
} // namespace android
