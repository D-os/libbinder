/*
 * Copyright (C) 2008 The Android Open Source Project
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

#ifndef ANDROID_BINDER_H
#define ANDROID_BINDER_H

#include <atomic>
#include <stdint.h>
#include <binder/IBinder.h>

// ---------------------------------------------------------------------------
namespace android {

namespace internal {
class Stability;
}

class BBinder : public IBinder
{
public:
                        BBinder();

    virtual const String16& getInterfaceDescriptor() const;
    virtual bool        isBinderAlive() const;
    virtual status_t    pingBinder();
    virtual status_t    dump(int fd, const Vector<String16>& args);

    // NOLINTNEXTLINE(google-default-arguments)
    virtual status_t    transact(   uint32_t code,
                                    const Parcel& data,
                                    Parcel* reply,
                                    uint32_t flags = 0) final;

    // NOLINTNEXTLINE(google-default-arguments)
    virtual status_t    linkToDeath(const sp<DeathRecipient>& recipient,
                                    void* cookie = nullptr,
                                    uint32_t flags = 0);

    // NOLINTNEXTLINE(google-default-arguments)
    virtual status_t    unlinkToDeath(  const wp<DeathRecipient>& recipient,
                                        void* cookie = nullptr,
                                        uint32_t flags = 0,
                                        wp<DeathRecipient>* outRecipient = nullptr);

    virtual void        attachObject(   const void* objectID,
                                        void* object,
                                        void* cleanupCookie,
                                        object_cleanup_func func) final;
    virtual void*       findObject(const void* objectID) const final;
    virtual void        detachObject(const void* objectID) final;

    virtual BBinder*    localBinder();

    bool                isRequestingSid();
    // This must be called before the object is sent to another process. Not thread safe.
    void                setRequestingSid(bool requestSid);

    sp<IBinder>         getExtension();
    // This must be called before the object is sent to another process. Not thread safe.
    void                setExtension(const sp<IBinder>& extension);

    // This must be called before the object is sent to another process. Not thread safe.
    //
    // This function will abort if improper parameters are set. This is like
    // sched_setscheduler. However, it sets the minimum scheduling policy
    // only for the duration that this specific binder object is handling the
    // call in a threadpool. By default, this API is set to SCHED_NORMAL/0. In
    // this case, the scheduling priority will not actually be modified from
    // binder defaults. See also IPCThreadState::disableBackgroundScheduling.
    //
    // Appropriate values are:
    // SCHED_NORMAL: -20 <= priority <= 19
    // SCHED_RR/SCHED_FIFO: 1 <= priority <= 99
    __attribute__((weak))
    void                setMinSchedulerPolicy(int policy, int priority);
    __attribute__((weak))
    int                 getMinSchedulerPolicy();
    __attribute__((weak))
    int                 getMinSchedulerPriority();

    pid_t               getDebugPid();

protected:
    virtual             ~BBinder();

    // NOLINTNEXTLINE(google-default-arguments)
    virtual status_t    onTransact( uint32_t code,
                                    const Parcel& data,
                                    Parcel* reply,
                                    uint32_t flags = 0);

private:
                        BBinder(const BBinder& o);
            BBinder&    operator=(const BBinder& o);

    class Extras;

    Extras*             getOrCreateExtras();

    std::atomic<Extras*> mExtras;

    friend ::android::internal::Stability;
    union {
        int32_t mStability;
        void* mReserved0;
    };
};

// ---------------------------------------------------------------------------

class BpRefBase : public virtual RefBase
{
protected:
    explicit                BpRefBase(const sp<IBinder>& o);
    virtual                 ~BpRefBase();
    virtual void            onFirstRef();
    virtual void            onLastStrongRef(const void* id);
    virtual bool            onIncStrongAttempted(uint32_t flags, const void* id);

    inline  IBinder*        remote()                { return mRemote; }
    inline  IBinder*        remote() const          { return mRemote; }

private:
                            BpRefBase(const BpRefBase& o);
    BpRefBase&              operator=(const BpRefBase& o);

    IBinder* const          mRemote;
    RefBase::weakref_type*  mRefs;
    std::atomic<int32_t>    mState;
};

} // namespace android

// ---------------------------------------------------------------------------

#endif // ANDROID_BINDER_H
