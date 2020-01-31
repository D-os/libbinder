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

// This AIDL is to test things that can't be tested in CtsNdkBinderTestCases
// because it requires libbinder_ndk implementation details or APIs not
// available to apps. Please prefer adding tests to CtsNdkBinderTestCases
// over here.

import IEmpty;

interface IBinderNdkUnitTest {
    void takeInterface(IEmpty test);
    void forceFlushCommands();
}
