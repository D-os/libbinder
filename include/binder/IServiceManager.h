/*
 * Copyright (C) 2005 The Android Open Source Project
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
#include <binder/IInterface.h>
#include <utils/Vector.h>
#include <utils/String16.h>
#include <optional>

namespace android {

// ----------------------------------------------------------------------

/**
 * Service manager for C++ services.
 *
 * IInterface is only for legacy ABI compatibility
 */
class IServiceManager : public IInterface
{
public:
    // for ABI compatibility
    virtual const String16& getInterfaceDescriptor() const;

    IServiceManager();
    virtual ~IServiceManager();

    /**
     * Must match values in IServiceManager.aidl
     */
    /* Allows services to dump sections according to priorities. */
    static const int DUMP_FLAG_PRIORITY_CRITICAL = 1 << 0;
    static const int DUMP_FLAG_PRIORITY_HIGH = 1 << 1;
    static const int DUMP_FLAG_PRIORITY_NORMAL = 1 << 2;
    /**
     * Services are by default registered with a DEFAULT dump priority. DEFAULT priority has the
     * same priority as NORMAL priority but the services are not called with dump priority
     * arguments.
     */
    static const int DUMP_FLAG_PRIORITY_DEFAULT = 1 << 3;
    static const int DUMP_FLAG_PRIORITY_ALL = DUMP_FLAG_PRIORITY_CRITICAL |
            DUMP_FLAG_PRIORITY_HIGH | DUMP_FLAG_PRIORITY_NORMAL | DUMP_FLAG_PRIORITY_DEFAULT;
    static const int DUMP_FLAG_PROTO = 1 << 4;

    /**
     * Retrieve an existing service, blocking for a few seconds if it doesn't yet exist. This
     * does polling. A more efficient way to make sure you unblock as soon as the service is
     * available is to use waitForService or to use service notifications.
     *
     * Warning: when using this API, typically, you should call it in a loop. It's dangerous to
     * assume that nullptr could mean that the service is not available. The service could just
     * be starting. Generally, whether a service exists, this information should be declared
     * externally (for instance, an Android feature might imply the existence of a service,
     * a system property, or in the case of services in the VINTF manifest, it can be checked
     * with isDeclared).
     */
    virtual sp<IBinder>         getService( const String16& name) const = 0;

    /**
     * Retrieve an existing service, non-blocking.
     */
    virtual sp<IBinder>         checkService( const String16& name) const = 0;

    /**
     * Register a service.
     */
    // NOLINTNEXTLINE(google-default-arguments)
    virtual status_t addService(const String16& name, const sp<IBinder>& service,
                                bool allowIsolated = false,
                                int dumpsysFlags = DUMP_FLAG_PRIORITY_DEFAULT) = 0;

    /**
     * Return list of all existing services.
     */
    // NOLINTNEXTLINE(google-default-arguments)
    virtual Vector<String16> listServices(int dumpsysFlags = DUMP_FLAG_PRIORITY_ALL) = 0;

    /**
     * Efficiently wait for a service.
     *
     * Returns nullptr only for permission problem or fatal error.
     */
    virtual sp<IBinder> waitForService(const String16& name) = 0;

    /**
     * Check if a service is declared (e.g. VINTF manifest).
     *
     * If this returns true, waitForService should always be able to return the
     * service.
     */
    virtual bool isDeclared(const String16& name) = 0;

    /**
     * Get all instances of a service as declared in the VINTF manifest
     */
    virtual Vector<String16> getDeclaredInstances(const String16& interface) = 0;

    /**
     * If this instance is updatable via an APEX, returns the APEX with which
     * this can be updated.
     */
    virtual std::optional<String16> updatableViaApex(const String16& name) = 0;

    /**
     * If this instance has declared remote connection information, returns
     * the ConnectionInfo.
     */
    struct ConnectionInfo {
        std::string ipAddress;
        unsigned int port;
    };
    virtual std::optional<ConnectionInfo> getConnectionInfo(const String16& name) = 0;

    struct LocalRegistrationCallback : public virtual RefBase {
        virtual void onServiceRegistration(const String16& instance, const sp<IBinder>& binder) = 0;
        virtual ~LocalRegistrationCallback() {}
    };

    virtual status_t registerForNotifications(const String16& name,
                                              const sp<LocalRegistrationCallback>& callback) = 0;

    virtual status_t unregisterForNotifications(const String16& name,
                                                const sp<LocalRegistrationCallback>& callback) = 0;

    struct ServiceDebugInfo {
        std::string name;
        int pid;
    };
    virtual std::vector<ServiceDebugInfo> getServiceDebugInfo() = 0;
};

sp<IServiceManager> defaultServiceManager();

/**
 * Directly set the default service manager. Only used for testing.
 * Note that the caller is responsible for caling this method
 * *before* any call to defaultServiceManager(); if the latter is
 * called first, setDefaultServiceManager() will abort.
 */
void setDefaultServiceManager(const sp<IServiceManager>& sm);

template<typename INTERFACE>
sp<INTERFACE> waitForService(const String16& name) {
    const sp<IServiceManager> sm = defaultServiceManager();
    return interface_cast<INTERFACE>(sm->waitForService(name));
}

template<typename INTERFACE>
sp<INTERFACE> waitForDeclaredService(const String16& name) {
    const sp<IServiceManager> sm = defaultServiceManager();
    if (!sm->isDeclared(name)) return nullptr;
    return interface_cast<INTERFACE>(sm->waitForService(name));
}

template <typename INTERFACE>
sp<INTERFACE> checkDeclaredService(const String16& name) {
    const sp<IServiceManager> sm = defaultServiceManager();
    if (!sm->isDeclared(name)) return nullptr;
    return interface_cast<INTERFACE>(sm->checkService(name));
}

template<typename INTERFACE>
sp<INTERFACE> waitForVintfService(
        const String16& instance = String16("default")) {
    return waitForDeclaredService<INTERFACE>(
        INTERFACE::descriptor + String16("/") + instance);
}

template<typename INTERFACE>
sp<INTERFACE> checkVintfService(
        const String16& instance = String16("default")) {
    return checkDeclaredService<INTERFACE>(
        INTERFACE::descriptor + String16("/") + instance);
}

template<typename INTERFACE>
status_t getService(const String16& name, sp<INTERFACE>* outService)
{
    const sp<IServiceManager> sm = defaultServiceManager();
    if (sm != nullptr) {
        *outService = interface_cast<INTERFACE>(sm->getService(name));
        if ((*outService) != nullptr) return NO_ERROR;
    }
    return NAME_NOT_FOUND;
}

bool checkCallingPermission(const String16& permission);
bool checkCallingPermission(const String16& permission,
                            int32_t* outPid, int32_t* outUid);
bool checkPermission(const String16& permission, pid_t pid, uid_t uid,
                     bool logPermissionFailure = true);

#ifndef __ANDROID__
// Create an IServiceManager that delegates the service manager on the device via adb.
// This is can be set as the default service manager at program start, so that
// defaultServiceManager() returns it:
//    int main() {
//        setDefaultServiceManager(createRpcDelegateServiceManager());
//        auto sm = defaultServiceManager();
//        // ...
//    }
// Resources are cleaned up when the object is destroyed.
//
// For each returned binder object, at most |maxOutgoingThreads| outgoing threads are instantiated.
// Hence, only |maxOutgoingThreads| calls can be made simultaneously. Additional calls are blocked
// if there are |maxOutgoingThreads| ongoing calls. See RpcSession::setMaxOutgoingThreads.
// If |maxOutgoingThreads| is not set, default is |RpcSession::kDefaultMaxOutgoingThreads|.
struct RpcDelegateServiceManagerOptions {
    std::optional<size_t> maxOutgoingThreads;
};
sp<IServiceManager> createRpcDelegateServiceManager(
        const RpcDelegateServiceManagerOptions& options);
#endif

} // namespace android
