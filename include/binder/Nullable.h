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

#include <memory>
#include <utility>

namespace android {

namespace aidl {

// nullable/make_nullable provide source-level compatibility between std::opional and std::unique_ptr
// usage:
//     nullable<Foo> a;
//     nullable<Foo> b = make_nullable<Foo>(...);
//     auto c = make_nullable<Foo>(...);
//     c.reset();
//     c = make_nullable<Foo>(...);
//     c = std::move(a);

template <typename T>
using nullable = std::unique_ptr<T>;

template <typename T, typename... Args>
inline nullable<T> make_nullable(Args&&... args) {
    return std::make_unique<T>(std::forward<Args>(args)...);
}

} // namespace aidl

} // namespace android