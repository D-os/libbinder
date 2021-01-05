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

#define LOG_TAG "AidlLazyServiceRegistrar"

#include <binder/LazyServiceRegistrar.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <android/os/BnClientCallback.h>
#include <android/os/IServiceManager.h>
#include <utils/Log.h>

namespace android {
namespace binder {
namespace internal {

using AidlServiceManager = android::os::IServiceManager;

class ClientCounterCallbackImpl : public ::android::os::BnClientCallback {
public:
    ClientCounterCallbackImpl() : mNumConnectedServices(0), mForcePersist(false) {}

    bool registerService(const sp<IBinder>& service, const std::string& name,
                         bool allowIsolated, int dumpFlags);
    void forcePersist(bool persist);

protected:
    Status onClients(const sp<IBinder>& service, bool clients) override;

private:
    /**
     * Unregisters all services that we can. If we can't unregister all, re-register other
     * services.
     */
    void tryShutdown();

    /**
     * Counter of the number of services that currently have at least one client.
     */
    size_t mNumConnectedServices;

    struct Service {
        sp<IBinder> service;
        bool allowIsolated;
        int dumpFlags;
    };
    /**
     * Map of registered names and services
     */
    std::map<std::string, Service> mRegisteredServices;

    bool mForcePersist;
};

class ClientCounterCallback {
public:
    ClientCounterCallback();

    bool registerService(const sp<IBinder>& service, const std::string& name,
                                            bool allowIsolated, int dumpFlags);

    /**
     * Set a flag to prevent services from automatically shutting down
     */
    void forcePersist(bool persist);

private:
    sp<ClientCounterCallbackImpl> mImpl;
};

bool ClientCounterCallbackImpl::registerService(const sp<IBinder>& service, const std::string& name,
                                            bool allowIsolated, int dumpFlags) {
    auto manager = interface_cast<AidlServiceManager>(asBinder(defaultServiceManager()));

    bool reRegister = mRegisteredServices.count(name) > 0;
    std::string regStr = (reRegister) ? "Re-registering" : "Registering";
    ALOGI("%s service %s", regStr.c_str(), name.c_str());

    if (!manager->addService(name.c_str(), service, allowIsolated, dumpFlags).isOk()) {
        ALOGE("Failed to register service %s", name.c_str());
        return false;
    }

    if (!reRegister) {
        if (!manager->registerClientCallback(name, service, this).isOk()) {
            ALOGE("Failed to add client callback for service %s", name.c_str());
            return false;
        }

        // Only add this when a service is added for the first time, as it is not removed
        mRegisteredServices[name] = {service, allowIsolated, dumpFlags};
    }

    return true;
}

void ClientCounterCallbackImpl::forcePersist(bool persist) {
    mForcePersist = persist;
    if(!mForcePersist) {
        // Attempt a shutdown in case the number of clients hit 0 while the flag was on
        tryShutdown();
    }
}

/**
 * onClients is oneway, so no need to worry about multi-threading. Note that this means multiple
 * invocations could occur on different threads however.
 */
Status ClientCounterCallbackImpl::onClients(const sp<IBinder>& service, bool clients) {
    if (clients) {
        mNumConnectedServices++;
    } else {
        mNumConnectedServices--;
    }

    ALOGI("Process has %zu (of %zu available) client(s) in use after notification %s has clients: %d",
          mNumConnectedServices, mRegisteredServices.size(),
          String8(service->getInterfaceDescriptor()).string(), clients);

    tryShutdown();
    return Status::ok();
}

void ClientCounterCallbackImpl::tryShutdown() {
    if(mNumConnectedServices > 0) {
        // Should only shut down if there are no clients
        return;
    }

    if(mForcePersist) {
        ALOGI("Shutdown prevented by forcePersist override flag.");
        return;
    }

    ALOGI("Trying to shut down the service. No clients in use for any service in process.");

    auto manager = interface_cast<AidlServiceManager>(asBinder(defaultServiceManager()));

    auto unRegisterIt = mRegisteredServices.begin();
    for (; unRegisterIt != mRegisteredServices.end(); ++unRegisterIt) {
        auto& entry = (*unRegisterIt);

        bool success = manager->tryUnregisterService(entry.first, entry.second.service).isOk();

        if (!success) {
            ALOGI("Failed to unregister service %s", entry.first.c_str());
            break;
        }
    }

    if (unRegisterIt == mRegisteredServices.end()) {
        ALOGI("Unregistered all clients and exiting");
        exit(EXIT_SUCCESS);
    }

    for (auto reRegisterIt = mRegisteredServices.begin(); reRegisterIt != unRegisterIt;
         reRegisterIt++) {
        auto& entry = (*reRegisterIt);

        // re-register entry
        if (!registerService(entry.second.service, entry.first, entry.second.allowIsolated,
                             entry.second.dumpFlags)) {
            // Must restart. Otherwise, clients will never be able to get a hold of this service.
            ALOGE("Bad state: could not re-register services");
        }
    }
}

ClientCounterCallback::ClientCounterCallback() {
      mImpl = new ClientCounterCallbackImpl();
}

bool ClientCounterCallback::registerService(const sp<IBinder>& service, const std::string& name,
                                            bool allowIsolated, int dumpFlags) {
    return mImpl->registerService(service, name, allowIsolated, dumpFlags);
}

void ClientCounterCallback::forcePersist(bool persist) {
    mImpl->forcePersist(persist);
}

}  // namespace internal

LazyServiceRegistrar::LazyServiceRegistrar() {
    mClientCC = std::make_shared<internal::ClientCounterCallback>();
}

LazyServiceRegistrar& LazyServiceRegistrar::getInstance() {
    static auto registrarInstance = new LazyServiceRegistrar();
    return *registrarInstance;
}

status_t LazyServiceRegistrar::registerService(const sp<IBinder>& service, const std::string& name,
                                               bool allowIsolated, int dumpFlags) {
    if (!mClientCC->registerService(service, name, allowIsolated, dumpFlags)) {
        return UNKNOWN_ERROR;
    }
    return OK;
}

void LazyServiceRegistrar::forcePersist(bool persist) {
    mClientCC->forcePersist(persist);
}

}  // namespace hardware
}  // namespace android