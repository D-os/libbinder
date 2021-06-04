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

#include <binder/Binder.h>

#include <atomic>

#include <android-base/unique_fd.h>
#include <binder/BpBinder.h>
#include <binder/IInterface.h>
#include <binder/IPCThreadState.h>
#include <binder/IResultReceiver.h>
#include <binder/IShellCallback.h>
#include <binder/Parcel.h>
#include <binder/RpcServer.h>
#include <private/android_filesystem_config.h>
#include <utils/misc.h>

#include <inttypes.h>
#include <linux/sched.h>
#include <stdio.h>

#include "RpcState.h"

namespace android {

// Service implementations inherit from BBinder and IBinder, and this is frozen
// in prebuilts.
#ifdef __LP64__
static_assert(sizeof(IBinder) == 24);
static_assert(sizeof(BBinder) == 40);
#else
static_assert(sizeof(IBinder) == 12);
static_assert(sizeof(BBinder) == 20);
#endif

#ifdef BINDER_RPC_DEV_SERVERS
constexpr const bool kEnableRpcDevServers = true;
#else
constexpr const bool kEnableRpcDevServers = false;
#endif

// ---------------------------------------------------------------------------

IBinder::IBinder()
    : RefBase()
{
}

IBinder::~IBinder()
{
}

// ---------------------------------------------------------------------------

sp<IInterface>  IBinder::queryLocalInterface(const String16& /*descriptor*/)
{
    return nullptr;
}

BBinder* IBinder::localBinder()
{
    return nullptr;
}

BpBinder* IBinder::remoteBinder()
{
    return nullptr;
}

bool IBinder::checkSubclass(const void* /*subclassID*/) const
{
    return false;
}


status_t IBinder::shellCommand(const sp<IBinder>& target, int in, int out, int err,
    Vector<String16>& args, const sp<IShellCallback>& callback,
    const sp<IResultReceiver>& resultReceiver)
{
    Parcel send;
    Parcel reply;
    send.writeFileDescriptor(in);
    send.writeFileDescriptor(out);
    send.writeFileDescriptor(err);
    const size_t numArgs = args.size();
    send.writeInt32(numArgs);
    for (size_t i = 0; i < numArgs; i++) {
        send.writeString16(args[i]);
    }
    send.writeStrongBinder(callback != nullptr ? IInterface::asBinder(callback) : nullptr);
    send.writeStrongBinder(resultReceiver != nullptr ? IInterface::asBinder(resultReceiver) : nullptr);
    return target->transact(SHELL_COMMAND_TRANSACTION, send, &reply);
}

status_t IBinder::getExtension(sp<IBinder>* out) {
    BBinder* local = this->localBinder();
    if (local != nullptr) {
        *out = local->getExtension();
        return OK;
    }

    BpBinder* proxy = this->remoteBinder();
    LOG_ALWAYS_FATAL_IF(proxy == nullptr);

    Parcel data;
    Parcel reply;
    status_t status = transact(EXTENSION_TRANSACTION, data, &reply);
    if (status != OK) return status;

    return reply.readNullableStrongBinder(out);
}

status_t IBinder::getDebugPid(pid_t* out) {
    BBinder* local = this->localBinder();
    if (local != nullptr) {
      *out = local->getDebugPid();
      return OK;
    }

    BpBinder* proxy = this->remoteBinder();
    LOG_ALWAYS_FATAL_IF(proxy == nullptr);

    Parcel data;
    Parcel reply;
    status_t status = transact(DEBUG_PID_TRANSACTION, data, &reply);
    if (status != OK) return status;

    int32_t pid;
    status = reply.readInt32(&pid);
    if (status != OK) return status;

    if (pid < 0 || pid > std::numeric_limits<pid_t>::max()) {
        return BAD_VALUE;
    }
    *out = pid;
    return OK;
}

status_t IBinder::setRpcClientDebug(android::base::unique_fd socketFd, uint32_t maxRpcThreads) {
    if constexpr (!kEnableRpcDevServers) {
        ALOGW("setRpcClientDebug disallowed because RPC is not enabled");
        return INVALID_OPERATION;
    }

    BBinder* local = this->localBinder();
    if (local != nullptr) {
        return local->BBinder::setRpcClientDebug(std::move(socketFd), maxRpcThreads);
    }

    BpBinder* proxy = this->remoteBinder();
    LOG_ALWAYS_FATAL_IF(proxy == nullptr, "binder object must be either local or remote");

    Parcel data;
    Parcel reply;
    status_t status;
    if (status = data.writeBool(socketFd.ok()); status != OK) return status;
    if (socketFd.ok()) {
        // writeUniqueFileDescriptor currently makes an unnecessary dup().
        status = data.writeFileDescriptor(socketFd.release(), true /* own */);
        if (status != OK) return status;
    }
    if (status = data.writeUint32(maxRpcThreads); status != OK) return status;
    return transact(SET_RPC_CLIENT_TRANSACTION, data, &reply);
}

// ---------------------------------------------------------------------------

class BBinder::Extras
{
public:
    // unlocked objects
    bool mRequestingSid = false;
    bool mInheritRt = false;
    sp<IBinder> mExtension;
    int mPolicy = SCHED_NORMAL;
    int mPriority = 0;

    // for below objects
    Mutex mLock;
    sp<RpcServer> mRpcServer;
    BpBinder::ObjectManager mObjects;
};

// ---------------------------------------------------------------------------

BBinder::BBinder() : mExtras(nullptr), mStability(0), mParceled(false) {}

bool BBinder::isBinderAlive() const
{
    return true;
}

status_t BBinder::pingBinder()
{
    return NO_ERROR;
}

const String16& BBinder::getInterfaceDescriptor() const
{
    // This is a local static rather than a global static,
    // to avoid static initializer ordering issues.
    static String16 sEmptyDescriptor;
    ALOGW("reached BBinder::getInterfaceDescriptor (this=%p)", this);
    return sEmptyDescriptor;
}

// NOLINTNEXTLINE(google-default-arguments)
status_t BBinder::transact(
    uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags)
{
    data.setDataPosition(0);

    if (reply != nullptr && (flags & FLAG_CLEAR_BUF)) {
        reply->markSensitive();
    }

    status_t err = NO_ERROR;
    switch (code) {
        case PING_TRANSACTION:
            err = pingBinder();
            break;
        case EXTENSION_TRANSACTION:
            err = reply->writeStrongBinder(getExtension());
            break;
        case DEBUG_PID_TRANSACTION:
            err = reply->writeInt32(getDebugPid());
            break;
        case SET_RPC_CLIENT_TRANSACTION: {
            err = setRpcClientDebug(data);
            break;
        }
        default:
            err = onTransact(code, data, reply, flags);
            break;
    }

    // In case this is being transacted on in the same process.
    if (reply != nullptr) {
        reply->setDataPosition(0);
    }

    return err;
}

// NOLINTNEXTLINE(google-default-arguments)
status_t BBinder::linkToDeath(
    const sp<DeathRecipient>& /*recipient*/, void* /*cookie*/,
    uint32_t /*flags*/)
{
    return INVALID_OPERATION;
}

// NOLINTNEXTLINE(google-default-arguments)
status_t BBinder::unlinkToDeath(
    const wp<DeathRecipient>& /*recipient*/, void* /*cookie*/,
    uint32_t /*flags*/, wp<DeathRecipient>* /*outRecipient*/)
{
    return INVALID_OPERATION;
}

status_t BBinder::dump(int /*fd*/, const Vector<String16>& /*args*/)
{
    return NO_ERROR;
}

void BBinder::attachObject(
    const void* objectID, void* object, void* cleanupCookie,
    object_cleanup_func func)
{
    Extras* e = getOrCreateExtras();
    if (!e) return; // out of memory

    AutoMutex _l(e->mLock);
    e->mObjects.attach(objectID, object, cleanupCookie, func);
}

void* BBinder::findObject(const void* objectID) const
{
    Extras* e = mExtras.load(std::memory_order_acquire);
    if (!e) return nullptr;

    AutoMutex _l(e->mLock);
    return e->mObjects.find(objectID);
}

void BBinder::detachObject(const void* objectID)
{
    Extras* e = mExtras.load(std::memory_order_acquire);
    if (!e) return;

    AutoMutex _l(e->mLock);
    e->mObjects.detach(objectID);
}

BBinder* BBinder::localBinder()
{
    return this;
}

bool BBinder::isRequestingSid()
{
    Extras* e = mExtras.load(std::memory_order_acquire);

    return e && e->mRequestingSid;
}

void BBinder::setRequestingSid(bool requestingSid)
{
    ALOGW_IF(mParceled,
             "setRequestingSid() should not be called after a binder object "
             "is parceled/sent to another process");

    Extras* e = mExtras.load(std::memory_order_acquire);

    if (!e) {
        // default is false. Most things don't need sids, so avoiding allocations when possible.
        if (!requestingSid) {
            return;
        }

        e = getOrCreateExtras();
        if (!e) return; // out of memory
    }

    e->mRequestingSid = requestingSid;
}

sp<IBinder> BBinder::getExtension() {
    Extras* e = mExtras.load(std::memory_order_acquire);
    if (e == nullptr) return nullptr;
    return e->mExtension;
}

void BBinder::setMinSchedulerPolicy(int policy, int priority) {
    ALOGW_IF(mParceled,
             "setMinSchedulerPolicy() should not be called after a binder object "
             "is parceled/sent to another process");

    switch (policy) {
    case SCHED_NORMAL:
      LOG_ALWAYS_FATAL_IF(priority < -20 || priority > 19, "Invalid priority for SCHED_NORMAL: %d", priority);
      break;
    case SCHED_RR:
    case SCHED_FIFO:
      LOG_ALWAYS_FATAL_IF(priority < 1 || priority > 99, "Invalid priority for sched %d: %d", policy, priority);
      break;
    default:
      LOG_ALWAYS_FATAL("Unrecognized scheduling policy: %d", policy);
    }

    Extras* e = mExtras.load(std::memory_order_acquire);

    if (e == nullptr) {
        // Avoid allocations if called with default.
        if (policy == SCHED_NORMAL && priority == 0) {
            return;
        }

        e = getOrCreateExtras();
        if (!e) return; // out of memory
    }

    e->mPolicy = policy;
    e->mPriority = priority;
}

int BBinder::getMinSchedulerPolicy() {
    Extras* e = mExtras.load(std::memory_order_acquire);
    if (e == nullptr) return SCHED_NORMAL;
    return e->mPolicy;
}

int BBinder::getMinSchedulerPriority() {
    Extras* e = mExtras.load(std::memory_order_acquire);
    if (e == nullptr) return 0;
    return e->mPriority;
}

bool BBinder::isInheritRt() {
    Extras* e = mExtras.load(std::memory_order_acquire);

    return e && e->mInheritRt;
}

void BBinder::setInheritRt(bool inheritRt) {
    ALOGW_IF(mParceled,
             "setInheritRt() should not be called after a binder object "
             "is parceled/sent to another process");

    Extras* e = mExtras.load(std::memory_order_acquire);

    if (!e) {
        if (!inheritRt) {
            return;
        }

        e = getOrCreateExtras();
        if (!e) return; // out of memory
    }

    e->mInheritRt = inheritRt;
}

pid_t BBinder::getDebugPid() {
    return getpid();
}

void BBinder::setExtension(const sp<IBinder>& extension) {
    ALOGW_IF(mParceled,
             "setExtension() should not be called after a binder object "
             "is parceled/sent to another process");

    Extras* e = getOrCreateExtras();
    e->mExtension = extension;
}

bool BBinder::wasParceled() {
    return mParceled;
}

void BBinder::setParceled() {
    mParceled = true;
}

status_t BBinder::setRpcClientDebug(const Parcel& data) {
    if constexpr (!kEnableRpcDevServers) {
        ALOGW("%s: disallowed because RPC is not enabled", __PRETTY_FUNCTION__);
        return INVALID_OPERATION;
    }
    uid_t uid = IPCThreadState::self()->getCallingUid();
    if (uid != AID_ROOT) {
        ALOGE("%s: not allowed because client %" PRIu32 " is not root", __PRETTY_FUNCTION__, uid);
        return PERMISSION_DENIED;
    }
    status_t status;
    bool hasSocketFd;
    android::base::unique_fd clientFd;
    uint32_t maxRpcThreads;

    if (status = data.readBool(&hasSocketFd); status != OK) return status;
    if (hasSocketFd) {
        if (status = data.readUniqueFileDescriptor(&clientFd); status != OK) return status;
    }
    if (status = data.readUint32(&maxRpcThreads); status != OK) return status;

    return setRpcClientDebug(std::move(clientFd), maxRpcThreads);
}

status_t BBinder::setRpcClientDebug(android::base::unique_fd socketFd, uint32_t maxRpcThreads) {
    if constexpr (!kEnableRpcDevServers) {
        ALOGW("%s: disallowed because RPC is not enabled", __PRETTY_FUNCTION__);
        return INVALID_OPERATION;
    }

    const int socketFdForPrint = socketFd.get();
    LOG_RPC_DETAIL("%s(%d, %" PRIu32 ")", __PRETTY_FUNCTION__, socketFdForPrint, maxRpcThreads);

    if (!socketFd.ok()) {
        ALOGE("%s: No socket FD provided.", __PRETTY_FUNCTION__);
        return BAD_VALUE;
    }
    if (maxRpcThreads <= 0) {
        ALOGE("%s: RPC is useless with %" PRIu32 " threads.", __PRETTY_FUNCTION__, maxRpcThreads);
        return BAD_VALUE;
    }

    // TODO(b/182914638): RPC and binder should share the same thread pool count.
    size_t binderThreadPoolMaxCount = ProcessState::self()->getThreadPoolMaxThreadCount();
    if (binderThreadPoolMaxCount <= 1) {
        ALOGE("%s: ProcessState thread pool max count is %zu. RPC is disabled for this service "
              "because RPC requires the service to support multithreading.",
              __PRETTY_FUNCTION__, binderThreadPoolMaxCount);
        return INVALID_OPERATION;
    }

    Extras* e = getOrCreateExtras();
    AutoMutex _l(e->mLock);
    if (e->mRpcServer != nullptr) {
        ALOGE("%s: Already have RPC client", __PRETTY_FUNCTION__);
        return ALREADY_EXISTS;
    }
    e->mRpcServer = RpcServer::make();
    LOG_ALWAYS_FATAL_IF(e->mRpcServer == nullptr, "RpcServer::make returns null");
    e->mRpcServer->iUnderstandThisCodeIsExperimentalAndIWillNotUseItInProduction();
    // Weak ref to avoid circular dependency: BBinder -> RpcServer -X-> BBinder
    e->mRpcServer->setRootObjectWeak(wp<BBinder>::fromExisting(this));
    e->mRpcServer->setupExternalServer(std::move(socketFd));
    e->mRpcServer->start();
    LOG_RPC_DETAIL("%s(%d, %" PRIu32 ") successful", __PRETTY_FUNCTION__, socketFdForPrint,
                   maxRpcThreads);
    return OK;
}

BBinder::~BBinder()
{
    Extras* e = mExtras.load(std::memory_order_relaxed);
    if (e) delete e;
}


// NOLINTNEXTLINE(google-default-arguments)
status_t BBinder::onTransact(
    uint32_t code, const Parcel& data, Parcel* reply, uint32_t /*flags*/)
{
    switch (code) {
        case INTERFACE_TRANSACTION:
            reply->writeString16(getInterfaceDescriptor());
            return NO_ERROR;

        case DUMP_TRANSACTION: {
            int fd = data.readFileDescriptor();
            int argc = data.readInt32();
            Vector<String16> args;
            for (int i = 0; i < argc && data.dataAvail() > 0; i++) {
               args.add(data.readString16());
            }
            return dump(fd, args);
        }

        case SHELL_COMMAND_TRANSACTION: {
            int in = data.readFileDescriptor();
            int out = data.readFileDescriptor();
            int err = data.readFileDescriptor();
            int argc = data.readInt32();
            Vector<String16> args;
            for (int i = 0; i < argc && data.dataAvail() > 0; i++) {
               args.add(data.readString16());
            }
            sp<IShellCallback> shellCallback = IShellCallback::asInterface(
                    data.readStrongBinder());
            sp<IResultReceiver> resultReceiver = IResultReceiver::asInterface(
                    data.readStrongBinder());

            // XXX can't add virtuals until binaries are updated.
            //return shellCommand(in, out, err, args, resultReceiver);
            (void)in;
            (void)out;
            (void)err;

            if (resultReceiver != nullptr) {
                resultReceiver->send(INVALID_OPERATION);
            }

            return NO_ERROR;
        }

        case SYSPROPS_TRANSACTION: {
            report_sysprop_change();
            return NO_ERROR;
        }

        default:
            return UNKNOWN_TRANSACTION;
    }
}

BBinder::Extras* BBinder::getOrCreateExtras()
{
    Extras* e = mExtras.load(std::memory_order_acquire);

    if (!e) {
        e = new Extras;
        Extras* expected = nullptr;
        if (!mExtras.compare_exchange_strong(expected, e,
                                             std::memory_order_release,
                                             std::memory_order_acquire)) {
            delete e;
            e = expected;  // Filled in by CAS
        }
        if (e == nullptr) return nullptr; // out of memory
    }

    return e;
}

// ---------------------------------------------------------------------------

enum {
    // This is used to transfer ownership of the remote binder from
    // the BpRefBase object holding it (when it is constructed), to the
    // owner of the BpRefBase object when it first acquires that BpRefBase.
    kRemoteAcquired = 0x00000001
};

BpRefBase::BpRefBase(const sp<IBinder>& o)
    : mRemote(o.get()), mRefs(nullptr), mState(0)
{
    extendObjectLifetime(OBJECT_LIFETIME_WEAK);

    if (mRemote) {
        mRemote->incStrong(this);           // Removed on first IncStrong().
        mRefs = mRemote->createWeak(this);  // Held for our entire lifetime.
    }
}

BpRefBase::~BpRefBase()
{
    if (mRemote) {
        if (!(mState.load(std::memory_order_relaxed)&kRemoteAcquired)) {
            mRemote->decStrong(this);
        }
        mRefs->decWeak(this);
    }
}

void BpRefBase::onFirstRef()
{
    mState.fetch_or(kRemoteAcquired, std::memory_order_relaxed);
}

void BpRefBase::onLastStrongRef(const void* /*id*/)
{
    if (mRemote) {
        mRemote->decStrong(this);
    }
}

bool BpRefBase::onIncStrongAttempted(uint32_t /*flags*/, const void* /*id*/)
{
    return mRemote ? mRefs->attemptIncStrong(this) : false;
}

// ---------------------------------------------------------------------------

} // namespace android
