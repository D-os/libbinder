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

#define LOG_TAG "BpBinder"
//#define LOG_NDEBUG 0

#include <binder/BpBinder.h>

#include <binder/IPCThreadState.h>
#include <binder/IResultReceiver.h>
#include <binder/RpcSession.h>
#include <binder/Stability.h>
#include <cutils/compiler.h>
#include <utils/Log.h>

#include <stdio.h>

//#undef ALOGV
//#define ALOGV(...) fprintf(stderr, __VA_ARGS__)

namespace android {

// ---------------------------------------------------------------------------

Mutex BpBinder::sTrackingLock;
std::unordered_map<int32_t, uint32_t> BpBinder::sTrackingMap;
std::unordered_map<int32_t, uint32_t> sLastLimitCallbackMap;
int BpBinder::sNumTrackedUids = 0;
std::atomic_bool BpBinder::sCountByUidEnabled(false);
binder_proxy_limit_callback BpBinder::sLimitCallback;
bool BpBinder::sBinderProxyThrottleCreate = false;

// Arbitrarily high value that probably distinguishes a bad behaving app
uint32_t BpBinder::sBinderProxyCountHighWatermark = 2500;
// Another arbitrary value a binder count needs to drop below before another callback will be called
uint32_t BpBinder::sBinderProxyCountLowWatermark = 2000;

enum {
    LIMIT_REACHED_MASK = 0x80000000,        // A flag denoting that the limit has been reached
    COUNTING_VALUE_MASK = 0x7FFFFFFF,       // A mask of the remaining bits for the count value
};

BpBinder::ObjectManager::ObjectManager()
{
}

BpBinder::ObjectManager::~ObjectManager()
{
    kill();
}

void BpBinder::ObjectManager::attach(
    const void* objectID, void* object, void* cleanupCookie,
    IBinder::object_cleanup_func func)
{
    entry_t e;
    e.object = object;
    e.cleanupCookie = cleanupCookie;
    e.func = func;

    if (mObjects.indexOfKey(objectID) >= 0) {
        ALOGE("Trying to attach object ID %p to binder ObjectManager %p with object %p, but object ID already in use",
                objectID, this,  object);
        return;
    }

    mObjects.add(objectID, e);
}

void* BpBinder::ObjectManager::find(const void* objectID) const
{
    const ssize_t i = mObjects.indexOfKey(objectID);
    if (i < 0) return nullptr;
    return mObjects.valueAt(i).object;
}

void BpBinder::ObjectManager::detach(const void* objectID)
{
    mObjects.removeItem(objectID);
}

void BpBinder::ObjectManager::kill()
{
    const size_t N = mObjects.size();
    ALOGV("Killing %zu objects in manager %p", N, this);
    for (size_t i=0; i<N; i++) {
        const entry_t& e = mObjects.valueAt(i);
        if (e.func != nullptr) {
            e.func(mObjects.keyAt(i), e.object, e.cleanupCookie);
        }
    }

    mObjects.clear();
}

// ---------------------------------------------------------------------------

sp<BpBinder> BpBinder::create(int32_t handle) {
    int32_t trackedUid = -1;
    if (sCountByUidEnabled) {
        trackedUid = IPCThreadState::self()->getCallingUid();
        AutoMutex _l(sTrackingLock);
        uint32_t trackedValue = sTrackingMap[trackedUid];
        if (CC_UNLIKELY(trackedValue & LIMIT_REACHED_MASK)) {
            if (sBinderProxyThrottleCreate) {
                return nullptr;
            }
            trackedValue = trackedValue & COUNTING_VALUE_MASK;
            uint32_t lastLimitCallbackAt = sLastLimitCallbackMap[trackedUid];

            if (trackedValue > lastLimitCallbackAt &&
                (trackedValue - lastLimitCallbackAt > sBinderProxyCountHighWatermark)) {
                ALOGE("Still too many binder proxy objects sent to uid %d from uid %d (%d proxies "
                      "held)",
                      getuid(), trackedUid, trackedValue);
                if (sLimitCallback) sLimitCallback(trackedUid);
                sLastLimitCallbackMap[trackedUid] = trackedValue;
            }
        } else {
            if ((trackedValue & COUNTING_VALUE_MASK) >= sBinderProxyCountHighWatermark) {
                ALOGE("Too many binder proxy objects sent to uid %d from uid %d (%d proxies held)",
                      getuid(), trackedUid, trackedValue);
                sTrackingMap[trackedUid] |= LIMIT_REACHED_MASK;
                if (sLimitCallback) sLimitCallback(trackedUid);
                sLastLimitCallbackMap[trackedUid] = trackedValue & COUNTING_VALUE_MASK;
                if (sBinderProxyThrottleCreate) {
                    ALOGI("Throttling binder proxy creates from uid %d in uid %d until binder proxy"
                          " count drops below %d",
                          trackedUid, getuid(), sBinderProxyCountLowWatermark);
                    return nullptr;
                }
            }
        }
        sTrackingMap[trackedUid]++;
    }
    return sp<BpBinder>::make(BinderHandle{handle}, trackedUid);
}

sp<BpBinder> BpBinder::create(const sp<RpcSession>& session, const RpcAddress& address) {
    LOG_ALWAYS_FATAL_IF(session == nullptr, "BpBinder::create null session");

    // These are not currently tracked, since there is no UID or other
    // identifier to track them with. However, if similar functionality is
    // needed, session objects keep track of all BpBinder objects on a
    // per-session basis.

    return sp<BpBinder>::make(RpcHandle{session, address});
}

BpBinder::BpBinder(Handle&& handle)
      : mStability(0),
        mHandle(handle),
        mAlive(true),
        mObitsSent(false),
        mObituaries(nullptr),
        mTrackedUid(-1) {
    extendObjectLifetime(OBJECT_LIFETIME_WEAK);
}

BpBinder::BpBinder(BinderHandle&& handle, int32_t trackedUid) : BpBinder(Handle(handle)) {
    mTrackedUid = trackedUid;

    ALOGV("Creating BpBinder %p handle %d\n", this, this->binderHandle());

    IPCThreadState::self()->incWeakHandle(this->binderHandle(), this);
}

BpBinder::BpBinder(RpcHandle&& handle) : BpBinder(Handle(handle)) {
    LOG_ALWAYS_FATAL_IF(rpcSession() == nullptr, "BpBinder created w/o session object");
}

bool BpBinder::isRpcBinder() const {
    return std::holds_alternative<RpcHandle>(mHandle);
}

const RpcAddress& BpBinder::rpcAddress() const {
    return std::get<RpcHandle>(mHandle).address;
}

const sp<RpcSession>& BpBinder::rpcSession() const {
    return std::get<RpcHandle>(mHandle).session;
}

int32_t BpBinder::binderHandle() const {
    return std::get<BinderHandle>(mHandle).handle;
}

bool BpBinder::isDescriptorCached() const {
    Mutex::Autolock _l(mLock);
    return mDescriptorCache.size() ? true : false;
}

const String16& BpBinder::getInterfaceDescriptor() const
{
    if (isDescriptorCached() == false) {
        sp<BpBinder> thiz = sp<BpBinder>::fromExisting(const_cast<BpBinder*>(this));

        Parcel data;
        data.markForBinder(thiz);
        Parcel reply;
        // do the IPC without a lock held.
        status_t err = thiz->transact(INTERFACE_TRANSACTION, data, &reply);
        if (err == NO_ERROR) {
            String16 res(reply.readString16());
            Mutex::Autolock _l(mLock);
            // mDescriptorCache could have been assigned while the lock was
            // released.
            if (mDescriptorCache.size() == 0)
                mDescriptorCache = res;
        }
    }

    // we're returning a reference to a non-static object here. Usually this
    // is not something smart to do, however, with binder objects it is
    // (usually) safe because they are reference-counted.

    return mDescriptorCache;
}

bool BpBinder::isBinderAlive() const
{
    return mAlive != 0;
}

status_t BpBinder::pingBinder()
{
    Parcel data;
    data.markForBinder(sp<BpBinder>::fromExisting(this));
    Parcel reply;
    return transact(PING_TRANSACTION, data, &reply);
}

status_t BpBinder::dump(int fd, const Vector<String16>& args)
{
    Parcel send;
    Parcel reply;
    send.writeFileDescriptor(fd);
    const size_t numArgs = args.size();
    send.writeInt32(numArgs);
    for (size_t i = 0; i < numArgs; i++) {
        send.writeString16(args[i]);
    }
    status_t err = transact(DUMP_TRANSACTION, send, &reply);
    return err;
}

// NOLINTNEXTLINE(google-default-arguments)
status_t BpBinder::transact(
    uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags)
{
    // Once a binder has died, it will never come back to life.
    if (mAlive) {
        bool privateVendor = flags & FLAG_PRIVATE_VENDOR;
        // don't send userspace flags to the kernel
        flags = flags & ~FLAG_PRIVATE_VENDOR;

        // user transactions require a given stability level
        if (code >= FIRST_CALL_TRANSACTION && code <= LAST_CALL_TRANSACTION) {
            using android::internal::Stability;

            auto category = Stability::getCategory(this);
            Stability::Level required = privateVendor ? Stability::VENDOR
                : Stability::getLocalLevel();

            if (CC_UNLIKELY(!Stability::check(category, required))) {
                ALOGE("Cannot do a user transaction on a %s binder (%s) in a %s context.",
                    category.debugString().c_str(),
                    String8(getInterfaceDescriptor()).c_str(),
                    Stability::levelString(required).c_str());
                return BAD_TYPE;
            }
        }

        status_t status;
        if (CC_UNLIKELY(isRpcBinder())) {
            status = rpcSession()->transact(rpcAddress(), code, data, reply, flags);
        } else {
            status = IPCThreadState::self()->transact(binderHandle(), code, data, reply, flags);
        }

        if (status == DEAD_OBJECT) mAlive = 0;

        return status;
    }

    return DEAD_OBJECT;
}

// NOLINTNEXTLINE(google-default-arguments)
status_t BpBinder::linkToDeath(
    const sp<DeathRecipient>& recipient, void* cookie, uint32_t flags)
{
    if (isRpcBinder()) return UNKNOWN_TRANSACTION;

    Obituary ob;
    ob.recipient = recipient;
    ob.cookie = cookie;
    ob.flags = flags;

    LOG_ALWAYS_FATAL_IF(recipient == nullptr,
                        "linkToDeath(): recipient must be non-NULL");

    {
        AutoMutex _l(mLock);

        if (!mObitsSent) {
            if (!mObituaries) {
                mObituaries = new Vector<Obituary>;
                if (!mObituaries) {
                    return NO_MEMORY;
                }
                ALOGV("Requesting death notification: %p handle %d\n", this, binderHandle());
                getWeakRefs()->incWeak(this);
                IPCThreadState* self = IPCThreadState::self();
                self->requestDeathNotification(binderHandle(), this);
                self->flushCommands();
            }
            ssize_t res = mObituaries->add(ob);
            return res >= (ssize_t)NO_ERROR ? (status_t)NO_ERROR : res;
        }
    }

    return DEAD_OBJECT;
}

// NOLINTNEXTLINE(google-default-arguments)
status_t BpBinder::unlinkToDeath(
    const wp<DeathRecipient>& recipient, void* cookie, uint32_t flags,
    wp<DeathRecipient>* outRecipient)
{
    if (isRpcBinder()) return UNKNOWN_TRANSACTION;

    AutoMutex _l(mLock);

    if (mObitsSent) {
        return DEAD_OBJECT;
    }

    const size_t N = mObituaries ? mObituaries->size() : 0;
    for (size_t i=0; i<N; i++) {
        const Obituary& obit = mObituaries->itemAt(i);
        if ((obit.recipient == recipient
                    || (recipient == nullptr && obit.cookie == cookie))
                && obit.flags == flags) {
            if (outRecipient != nullptr) {
                *outRecipient = mObituaries->itemAt(i).recipient;
            }
            mObituaries->removeAt(i);
            if (mObituaries->size() == 0) {
                ALOGV("Clearing death notification: %p handle %d\n", this, binderHandle());
                IPCThreadState* self = IPCThreadState::self();
                self->clearDeathNotification(binderHandle(), this);
                self->flushCommands();
                delete mObituaries;
                mObituaries = nullptr;
            }
            return NO_ERROR;
        }
    }

    return NAME_NOT_FOUND;
}

void BpBinder::sendObituary()
{
    LOG_ALWAYS_FATAL_IF(isRpcBinder(), "Cannot send obituary for remote binder.");

    ALOGV("Sending obituary for proxy %p handle %d, mObitsSent=%s\n", this, binderHandle(),
          mObitsSent ? "true" : "false");

    mAlive = 0;
    if (mObitsSent) return;

    mLock.lock();
    Vector<Obituary>* obits = mObituaries;
    if(obits != nullptr) {
        ALOGV("Clearing sent death notification: %p handle %d\n", this, binderHandle());
        IPCThreadState* self = IPCThreadState::self();
        self->clearDeathNotification(binderHandle(), this);
        self->flushCommands();
        mObituaries = nullptr;
    }
    mObitsSent = 1;
    mLock.unlock();

    ALOGV("Reporting death of proxy %p for %zu recipients\n",
        this, obits ? obits->size() : 0U);

    if (obits != nullptr) {
        const size_t N = obits->size();
        for (size_t i=0; i<N; i++) {
            reportOneDeath(obits->itemAt(i));
        }

        delete obits;
    }
}

void BpBinder::reportOneDeath(const Obituary& obit)
{
    sp<DeathRecipient> recipient = obit.recipient.promote();
    ALOGV("Reporting death to recipient: %p\n", recipient.get());
    if (recipient == nullptr) return;

    recipient->binderDied(wp<BpBinder>::fromExisting(this));
}


void BpBinder::attachObject(
    const void* objectID, void* object, void* cleanupCookie,
    object_cleanup_func func)
{
    AutoMutex _l(mLock);
    ALOGV("Attaching object %p to binder %p (manager=%p)", object, this, &mObjects);
    mObjects.attach(objectID, object, cleanupCookie, func);
}

void* BpBinder::findObject(const void* objectID) const
{
    AutoMutex _l(mLock);
    return mObjects.find(objectID);
}

void BpBinder::detachObject(const void* objectID)
{
    AutoMutex _l(mLock);
    mObjects.detach(objectID);
}

BpBinder* BpBinder::remoteBinder()
{
    return this;
}

BpBinder::~BpBinder()
{
    ALOGV("Destroying BpBinder %p handle %d\n", this, binderHandle());

    if (CC_UNLIKELY(isRpcBinder())) return;

    IPCThreadState* ipc = IPCThreadState::self();

    if (mTrackedUid >= 0) {
        AutoMutex _l(sTrackingLock);
        uint32_t trackedValue = sTrackingMap[mTrackedUid];
        if (CC_UNLIKELY((trackedValue & COUNTING_VALUE_MASK) == 0)) {
            ALOGE("Unexpected Binder Proxy tracking decrement in %p handle %d\n", this,
                  binderHandle());
        } else {
            if (CC_UNLIKELY(
                (trackedValue & LIMIT_REACHED_MASK) &&
                ((trackedValue & COUNTING_VALUE_MASK) <= sBinderProxyCountLowWatermark)
                )) {
                ALOGI("Limit reached bit reset for uid %d (fewer than %d proxies from uid %d held)",
                      getuid(), sBinderProxyCountLowWatermark, mTrackedUid);
                sTrackingMap[mTrackedUid] &= ~LIMIT_REACHED_MASK;
                sLastLimitCallbackMap.erase(mTrackedUid);
            }
            if (--sTrackingMap[mTrackedUid] == 0) {
                sTrackingMap.erase(mTrackedUid);
            }
        }
    }

    if (ipc) {
        ipc->expungeHandle(binderHandle(), this);
        ipc->decWeakHandle(binderHandle());
    }
}

void BpBinder::onFirstRef()
{
    ALOGV("onFirstRef BpBinder %p handle %d\n", this, binderHandle());
    if (CC_UNLIKELY(isRpcBinder())) return;
    IPCThreadState* ipc = IPCThreadState::self();
    if (ipc) ipc->incStrongHandle(binderHandle(), this);
}

void BpBinder::onLastStrongRef(const void* /*id*/)
{
    ALOGV("onLastStrongRef BpBinder %p handle %d\n", this, binderHandle());
    if (CC_UNLIKELY(isRpcBinder())) {
        (void)rpcSession()->sendDecStrong(rpcAddress());
        return;
    }
    IF_ALOGV() {
        printRefs();
    }
    IPCThreadState* ipc = IPCThreadState::self();
    if (ipc) ipc->decStrongHandle(binderHandle());

    mLock.lock();
    Vector<Obituary>* obits = mObituaries;
    if(obits != nullptr) {
        if (!obits->isEmpty()) {
            ALOGI("onLastStrongRef automatically unlinking death recipients: %s",
                  mDescriptorCache.size() ? String8(mDescriptorCache).c_str() : "<uncached descriptor>");
        }

        if (ipc) ipc->clearDeathNotification(binderHandle(), this);
        mObituaries = nullptr;
    }
    mLock.unlock();

    if (obits != nullptr) {
        // XXX Should we tell any remaining DeathRecipient
        // objects that the last strong ref has gone away, so they
        // are no longer linked?
        delete obits;
    }
}

bool BpBinder::onIncStrongAttempted(uint32_t /*flags*/, const void* /*id*/)
{
    // RPC binder doesn't currently support inc from weak binders
    if (CC_UNLIKELY(isRpcBinder())) return false;

    ALOGV("onIncStrongAttempted BpBinder %p handle %d\n", this, binderHandle());
    IPCThreadState* ipc = IPCThreadState::self();
    return ipc ? ipc->attemptIncStrongHandle(binderHandle()) == NO_ERROR : false;
}

uint32_t BpBinder::getBinderProxyCount(uint32_t uid)
{
    AutoMutex _l(sTrackingLock);
    auto it = sTrackingMap.find(uid);
    if (it != sTrackingMap.end()) {
        return it->second & COUNTING_VALUE_MASK;
    }
    return 0;
}

void BpBinder::getCountByUid(Vector<uint32_t>& uids, Vector<uint32_t>& counts)
{
    AutoMutex _l(sTrackingLock);
    uids.setCapacity(sTrackingMap.size());
    counts.setCapacity(sTrackingMap.size());
    for (const auto& it : sTrackingMap) {
        uids.push_back(it.first);
        counts.push_back(it.second & COUNTING_VALUE_MASK);
    }
}

void BpBinder::enableCountByUid() { sCountByUidEnabled.store(true); }
void BpBinder::disableCountByUid() { sCountByUidEnabled.store(false); }
void BpBinder::setCountByUidEnabled(bool enable) { sCountByUidEnabled.store(enable); }

void BpBinder::setLimitCallback(binder_proxy_limit_callback cb) {
    AutoMutex _l(sTrackingLock);
    sLimitCallback = cb;
}

void BpBinder::setBinderProxyCountWatermarks(int high, int low) {
    AutoMutex _l(sTrackingLock);
    sBinderProxyCountHighWatermark = high;
    sBinderProxyCountLowWatermark = low;
}

// ---------------------------------------------------------------------------

} // namespace android
