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

#define LOG_TAG "ServiceManager"

#include <binder/IServiceManager.h>

#include <android/os/BnServiceCallback.h>
#include <android/os/IServiceManager.h>
#include <binder/IPCThreadState.h>
#include <binder/Parcel.h>
#include <utils/Log.h>
#include <utils/String8.h>
#include <utils/SystemClock.h>

#ifndef __ANDROID_VNDK__
#include <binder/IPermissionController.h>
#endif

#ifdef __ANDROID__
#include <cutils/properties.h>
#endif

#include "Static.h"

#include <unistd.h>

namespace android {

using AidlServiceManager = android::os::IServiceManager;
using android::binder::Status;

sp<IServiceManager> defaultServiceManager()
{
    static Mutex gDefaultServiceManagerLock;
    static sp<IServiceManager> gDefaultServiceManager;

    if (gDefaultServiceManager != nullptr) return gDefaultServiceManager;

    {
        AutoMutex _l(gDefaultServiceManagerLock);
        while (gDefaultServiceManager == nullptr) {
            gDefaultServiceManager = interface_cast<IServiceManager>(
                ProcessState::self()->getContextObject(nullptr));
            if (gDefaultServiceManager == nullptr)
                sleep(1);
        }
    }

    return gDefaultServiceManager;
}

#if !defined(__ANDROID_VNDK__) && defined(__ANDROID__)
// IPermissionController is not accessible to vendors

bool checkCallingPermission(const String16& permission)
{
    return checkCallingPermission(permission, nullptr, nullptr);
}

static String16 _permission("permission");


bool checkCallingPermission(const String16& permission, int32_t* outPid, int32_t* outUid)
{
    IPCThreadState* ipcState = IPCThreadState::self();
    pid_t pid = ipcState->getCallingPid();
    uid_t uid = ipcState->getCallingUid();
    if (outPid) *outPid = pid;
    if (outUid) *outUid = uid;
    return checkPermission(permission, pid, uid);
}

bool checkPermission(const String16& permission, pid_t pid, uid_t uid)
{
    static Mutex gPermissionControllerLock;
    static sp<IPermissionController> gPermissionController;

    sp<IPermissionController> pc;
    gPermissionControllerLock.lock();
    pc = gPermissionController;
    gPermissionControllerLock.unlock();

    int64_t startTime = 0;

    while (true) {
        if (pc != nullptr) {
            bool res = pc->checkPermission(permission, pid, uid);
            if (res) {
                if (startTime != 0) {
                    ALOGI("Check passed after %d seconds for %s from uid=%d pid=%d",
                            (int)((uptimeMillis()-startTime)/1000),
                            String8(permission).string(), uid, pid);
                }
                return res;
            }

            // Is this a permission failure, or did the controller go away?
            if (IInterface::asBinder(pc)->isBinderAlive()) {
                ALOGW("Permission failure: %s from uid=%d pid=%d",
                        String8(permission).string(), uid, pid);
                return false;
            }

            // Object is dead!
            gPermissionControllerLock.lock();
            if (gPermissionController == pc) {
                gPermissionController = nullptr;
            }
            gPermissionControllerLock.unlock();
        }

        // Need to retrieve the permission controller.
        sp<IBinder> binder = defaultServiceManager()->checkService(_permission);
        if (binder == nullptr) {
            // Wait for the permission controller to come back...
            if (startTime == 0) {
                startTime = uptimeMillis();
                ALOGI("Waiting to check permission %s from uid=%d pid=%d",
                        String8(permission).string(), uid, pid);
            }
            sleep(1);
        } else {
            pc = interface_cast<IPermissionController>(binder);
            // Install the new permission controller, and try again.
            gPermissionControllerLock.lock();
            gPermissionController = pc;
            gPermissionControllerLock.unlock();
        }
    }
}

#endif //__ANDROID_VNDK__

// ----------------------------------------------------------------------

class BpServiceManager : public BpInterface<IServiceManager>
{
public:
    explicit BpServiceManager(const sp<IBinder>& impl)
        : BpInterface<IServiceManager>(impl),
          mTheRealServiceManager(interface_cast<AidlServiceManager>(impl))
    {
    }

    sp<IBinder> getService(const String16& name) const override
    {
        static bool gSystemBootCompleted = false;

        sp<IBinder> svc = checkService(name);
        if (svc != nullptr) return svc;

        const bool isVendorService =
            strcmp(ProcessState::self()->getDriverName().c_str(), "/dev/vndbinder") == 0;
        const long timeout = uptimeMillis() + 5000;
        // Vendor code can't access system properties
        if (!gSystemBootCompleted && !isVendorService) {
#ifdef __ANDROID__
            char bootCompleted[PROPERTY_VALUE_MAX];
            property_get("sys.boot_completed", bootCompleted, "0");
            gSystemBootCompleted = strcmp(bootCompleted, "1") == 0 ? true : false;
#else
            gSystemBootCompleted = true;
#endif
        }
        // retry interval in millisecond; note that vendor services stay at 100ms
        const long sleepTime = gSystemBootCompleted ? 1000 : 100;

        int n = 0;
        while (uptimeMillis() < timeout) {
            n++;
            ALOGI("Waiting for service '%s' on '%s'...", String8(name).string(),
                ProcessState::self()->getDriverName().c_str());
            usleep(1000*sleepTime);

            sp<IBinder> svc = checkService(name);
            if (svc != nullptr) return svc;
        }
        ALOGW("Service %s didn't start. Returning NULL", String8(name).string());
        return nullptr;
    }

    sp<IBinder> checkService(const String16& name) const override {
        sp<IBinder> ret;
        if (!mTheRealServiceManager->checkService(String8(name).c_str(), &ret).isOk()) {
            return nullptr;
        }
        return ret;
    }

    status_t addService(const String16& name, const sp<IBinder>& service,
                        bool allowIsolated, int dumpsysPriority) override {
        Status status = mTheRealServiceManager->addService(String8(name).c_str(), service, allowIsolated, dumpsysPriority);
        return status.exceptionCode();
    }

    virtual Vector<String16> listServices(int dumpsysPriority) {
        std::vector<std::string> ret;
        if (!mTheRealServiceManager->listServices(dumpsysPriority, &ret).isOk()) {
            return {};
        }

        Vector<String16> res;
        res.setCapacity(ret.size());
        for (const std::string& name : ret) {
            res.push(String16(name.c_str()));
        }
        return res;
    }

    sp<IBinder> waitForService(const String16& name16) override {
        class Waiter : public android::os::BnServiceCallback {
            Status onRegistration(const std::string& /*name*/,
                                  const sp<IBinder>& binder) override {
                std::unique_lock<std::mutex> lock(mMutex);
                mBinder = binder;
                lock.unlock();
                mCv.notify_one();
                return Status::ok();
            }
        public:
            sp<IBinder> mBinder;
            std::mutex mMutex;
            std::condition_variable mCv;
        };

        const std::string name = String8(name16).c_str();

        sp<IBinder> out;
        if (!mTheRealServiceManager->getService(name, &out).isOk()) {
            return nullptr;
        }
        if(out != nullptr) return out;

        sp<Waiter> waiter = new Waiter;
        if (!mTheRealServiceManager->registerForNotifications(
                name, waiter).isOk()) {
            return nullptr;
        }

        while(true) {
            {
                std::unique_lock<std::mutex> lock(waiter->mMutex);
                using std::literals::chrono_literals::operator""s;
                waiter->mCv.wait_for(lock, 1s, [&] {
                    return waiter->mBinder != nullptr;
                });
                if (waiter->mBinder != nullptr) return waiter->mBinder;
            }

            // Handle race condition for lazy services. Here is what can happen:
            // - the service dies (not processed by init yet).
            // - sm processes death notification.
            // - sm gets getService and calls init to start service.
            // - init gets the start signal, but the service already appears
            //   started, so it does nothing.
            // - init gets death signal, but doesn't know it needs to restart
            //   the service
            // - we need to request service again to get it to start
            if (!mTheRealServiceManager->getService(name, &out).isOk()) {
                return nullptr;
            }
            if(out != nullptr) return out;

            ALOGW("Waited one second for %s", name.c_str());
        }
    }

private:
    sp<AidlServiceManager> mTheRealServiceManager;
};

IMPLEMENT_META_INTERFACE(ServiceManager, "android.os.IServiceManager");

}; // namespace android
