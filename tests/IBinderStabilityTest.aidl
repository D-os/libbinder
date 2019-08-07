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

import IBinderStabilityTestSub;

// DO NOT EVER IN A MILLION YEARS WRITE AN INTERFACE LIKE THIS!
// THIS IS ONLY FOR TESTING!
interface IBinderStabilityTest {
    // DO NOT EVER IN A MILLION YEARS WRITE AN INTERFACE LIKE THIS!
    // THIS IS ONLY FOR TESTING!
    void sendBinder(IBinderStabilityTestSub binder);

    // DO NOT EVER IN A MILLION YEARS WRITE AN INTERFACE LIKE THIS!
    // THIS IS ONLY FOR TESTING!
    void sendAndCallBinder(IBinderStabilityTestSub binder);

    // DO NOT EVER IN A MILLION YEARS WRITE AN INTERFACE LIKE THIS!
    // THIS IS ONLY FOR TESTING!
    IBinderStabilityTestSub returnNoStabilityBinder();

    // DO NOT EVER IN A MILLION YEARS WRITE AN INTERFACE LIKE THIS!
    // THIS IS ONLY FOR TESTING!
    IBinderStabilityTestSub returnLocalStabilityBinder();

    // DO NOT EVER IN A MILLION YEARS WRITE AN INTERFACE LIKE THIS!
    // THIS IS ONLY FOR TESTING!
    IBinderStabilityTestSub returnVintfStabilityBinder();

    // DO NOT EVER IN A MILLION YEARS WRITE AN INTERFACE LIKE THIS!
    // THIS IS ONLY FOR TESTING!
    IBinderStabilityTestSub returnVendorStabilityBinder();
}
// DO NOT EVER IN A MILLION YEARS WRITE AN INTERFACE LIKE THIS!
// THIS IS ONLY FOR TESTING!
// Construct and return a binder with a specific stability
