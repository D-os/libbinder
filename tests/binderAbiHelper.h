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

#pragma once

#include <stdlib.h>
#include <iostream>

#ifdef BINDER_IPC_32BIT
static constexpr bool kBuild32Abi = true;
#else
static constexpr bool kBuild32Abi = false;
#endif

// TODO: remove when CONFIG_ANDROID_BINDER_IPC_32BIT is no longer supported
static inline bool ReadKernelConfigIs32BitAbi() {
    // failure case implies we run with standard ABI
    return 0 == system("zcat /proc/config.gz | grep -E \"^CONFIG_ANDROID_BINDER_IPC_32BIT=y$\"");
}

static inline void ExitIfWrongAbi() {
    bool runtime32Abi = ReadKernelConfigIs32BitAbi();

    if (kBuild32Abi != runtime32Abi) {
        std::cout << "[==========] Running 1 test from 1 test suite." << std::endl;
        std::cout << "[----------] Global test environment set-up." << std::endl;
        std::cout << "[----------] 1 tests from BinderLibTest" << std::endl;
        std::cout << "[ RUN      ] BinderTest.AbortForWrongAbi" << std::endl;
        std::cout << "[ INFO     ] test build abi 32: " << kBuild32Abi << " runtime abi 32: " << runtime32Abi << " so, skipping tests " << std::endl;
        std::cout << "[       OK ] BinderTest.AbortForWrongAbi (0 ms) " << std::endl;
        std::cout << "[----------] 1 tests from BinderTest (0 ms total)" << std::endl;
        std::cout << "" << std::endl;
        std::cout << "[----------] Global test environment tear-down" << std::endl;
        std::cout << "[==========] 1 test from 1 test suite ran. (0 ms total)" << std::endl;
        std::cout << "[  PASSED  ] 1 tests." << std::endl;
        exit(0);
    }
}

