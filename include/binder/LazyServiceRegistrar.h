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

#pragma once

#include <binder/IServiceManager.h>
#include <binder/Status.h>
#include <utils/StrongPointer.h>

namespace android {
namespace binder {
namespace internal {
class ClientCounterCallback;
}  // namespace internal

/** Exits when all services registered through this object have 0 clients */
class LazyServiceRegistrar {
   public:
     static LazyServiceRegistrar& getInstance();
     status_t registerService(const sp<IBinder>& service,
                              const std::string& name = "default",
                              bool allowIsolated = false,
                              int dumpFlags = IServiceManager::DUMP_FLAG_PRIORITY_DEFAULT);
     /**
      * Force the service to persist, even when it has 0 clients.
      * If setting this flag from the server side, make sure to do so before calling registerService,
      * or there may be a race with the default dynamic shutdown.
      */
     void forcePersist(bool persist);

   private:
     std::shared_ptr<internal::ClientCounterCallback> mClientCC;
     LazyServiceRegistrar();
};

}  // namespace binder
}  // namespace android