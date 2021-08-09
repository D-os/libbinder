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
     * Whether this has been triggered.
     */
    bool isTriggered();

    /**
     * Poll for a read event.
     *
     * event - for pollfd
     *
     * Return:
     *   true - time to read!
     *   false - trigger happened
     */
    status_t triggerablePoll(base::borrowed_fd fd, int16_t event);

private:
    base::unique_fd mWrite;
    base::unique_fd mRead;
};
} // namespace android
