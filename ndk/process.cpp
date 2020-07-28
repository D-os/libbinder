/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <android/binder_process.h>

#include <mutex>

#include <android-base/logging.h>
#include <binder/IPCThreadState.h>

using ::android::IPCThreadState;
using ::android::ProcessState;

void ABinderProcess_startThreadPool() {
    ProcessState::self()->startThreadPool();
    ProcessState::self()->giveThreadPoolName();
}
bool ABinderProcess_setThreadPoolMaxThreadCount(uint32_t numThreads) {
    return ProcessState::self()->setThreadPoolMaxThreadCount(numThreads) == 0;
}
void ABinderProcess_joinThreadPool() {
    IPCThreadState::self()->joinThreadPool();
}

binder_status_t ABinderProcess_setupPolling(int* fd) {
    return IPCThreadState::self()->setupPolling(fd);
}

binder_status_t ABinderProcess_handlePolledCommands() {
    return IPCThreadState::self()->handlePolledCommands();
}
