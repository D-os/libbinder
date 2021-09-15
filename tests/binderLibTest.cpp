/*
 * Copyright (C) 2014 The Android Open Source Project
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

#include <errno.h>
#include <fcntl.h>
#include <fstream>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <thread>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <binder/Binder.h>
#include <binder/IBinder.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>

#include <linux/sched.h>
#include <sys/epoll.h>
#include <sys/prctl.h>

#include "../binder_module.h"
#include "binderAbiHelper.h"

#define ARRAY_SIZE(array) (sizeof array / sizeof array[0])

using namespace android;
using testing::Not;

// e.g. EXPECT_THAT(expr, StatusEq(OK)) << "additional message";
MATCHER_P(StatusEq, expected, (negation ? "not " : "") + statusToString(expected)) {
    *result_listener << statusToString(arg);
    return expected == arg;
}

static ::testing::AssertionResult IsPageAligned(void *buf) {
    if (((unsigned long)buf & ((unsigned long)PAGE_SIZE - 1)) == 0)
        return ::testing::AssertionSuccess();
    else
        return ::testing::AssertionFailure() << buf << " is not page aligned";
}

static testing::Environment* binder_env;
static char *binderservername;
static char *binderserversuffix;
static char binderserverarg[] = "--binderserver";

static constexpr int kSchedPolicy = SCHED_RR;
static constexpr int kSchedPriority = 7;
static constexpr int kSchedPriorityMore = 8;

static String16 binderLibTestServiceName = String16("test.binderLib");

enum BinderLibTestTranscationCode {
    BINDER_LIB_TEST_NOP_TRANSACTION = IBinder::FIRST_CALL_TRANSACTION,
    BINDER_LIB_TEST_REGISTER_SERVER,
    BINDER_LIB_TEST_ADD_SERVER,
    BINDER_LIB_TEST_ADD_POLL_SERVER,
    BINDER_LIB_TEST_CALL_BACK,
    BINDER_LIB_TEST_CALL_BACK_VERIFY_BUF,
    BINDER_LIB_TEST_DELAYED_CALL_BACK,
    BINDER_LIB_TEST_NOP_CALL_BACK,
    BINDER_LIB_TEST_GET_SELF_TRANSACTION,
    BINDER_LIB_TEST_GET_ID_TRANSACTION,
    BINDER_LIB_TEST_INDIRECT_TRANSACTION,
    BINDER_LIB_TEST_SET_ERROR_TRANSACTION,
    BINDER_LIB_TEST_GET_STATUS_TRANSACTION,
    BINDER_LIB_TEST_ADD_STRONG_REF_TRANSACTION,
    BINDER_LIB_TEST_LINK_DEATH_TRANSACTION,
    BINDER_LIB_TEST_WRITE_FILE_TRANSACTION,
    BINDER_LIB_TEST_WRITE_PARCEL_FILE_DESCRIPTOR_TRANSACTION,
    BINDER_LIB_TEST_EXIT_TRANSACTION,
    BINDER_LIB_TEST_DELAYED_EXIT_TRANSACTION,
    BINDER_LIB_TEST_GET_PTR_SIZE_TRANSACTION,
    BINDER_LIB_TEST_CREATE_BINDER_TRANSACTION,
    BINDER_LIB_TEST_GET_WORK_SOURCE_TRANSACTION,
    BINDER_LIB_TEST_GET_SCHEDULING_POLICY,
    BINDER_LIB_TEST_NOP_TRANSACTION_WAIT,
    BINDER_LIB_TEST_GETPID,
    BINDER_LIB_TEST_ECHO_VECTOR,
    BINDER_LIB_TEST_REJECT_BUF,
    BINDER_LIB_TEST_CAN_GET_SID,
};

pid_t start_server_process(int arg2, bool usePoll = false)
{
    int ret;
    pid_t pid;
    status_t status;
    int pipefd[2];
    char stri[16];
    char strpipefd1[16];
    char usepoll[2];
    char *childargv[] = {
        binderservername,
        binderserverarg,
        stri,
        strpipefd1,
        usepoll,
        binderserversuffix,
        nullptr
    };

    ret = pipe(pipefd);
    if (ret < 0)
        return ret;

    snprintf(stri, sizeof(stri), "%d", arg2);
    snprintf(strpipefd1, sizeof(strpipefd1), "%d", pipefd[1]);
    snprintf(usepoll, sizeof(usepoll), "%d", usePoll ? 1 : 0);

    pid = fork();
    if (pid == -1)
        return pid;
    if (pid == 0) {
        prctl(PR_SET_PDEATHSIG, SIGHUP);
        close(pipefd[0]);
        execv(binderservername, childargv);
        status = -errno;
        write(pipefd[1], &status, sizeof(status));
        fprintf(stderr, "execv failed, %s\n", strerror(errno));
        _exit(EXIT_FAILURE);
    }
    close(pipefd[1]);
    ret = read(pipefd[0], &status, sizeof(status));
    //printf("pipe read returned %d, status %d\n", ret, status);
    close(pipefd[0]);
    if (ret == sizeof(status)) {
        ret = status;
    } else {
        kill(pid, SIGKILL);
        if (ret >= 0) {
            ret = NO_INIT;
        }
    }
    if (ret < 0) {
        wait(nullptr);
        return ret;
    }
    return pid;
}

class BinderLibTestEnv : public ::testing::Environment {
    public:
        BinderLibTestEnv() {}
        sp<IBinder> getServer(void) {
            return m_server;
        }

    private:
        virtual void SetUp() {
            m_serverpid = start_server_process(0);
            //printf("m_serverpid %d\n", m_serverpid);
            ASSERT_GT(m_serverpid, 0);

            sp<IServiceManager> sm = defaultServiceManager();
            //printf("%s: pid %d, get service\n", __func__, m_pid);
            m_server = sm->getService(binderLibTestServiceName);
            ASSERT_TRUE(m_server != nullptr);
            //printf("%s: pid %d, get service done\n", __func__, m_pid);
        }
        virtual void TearDown() {
            status_t ret;
            Parcel data, reply;
            int exitStatus;
            pid_t pid;

            //printf("%s: pid %d\n", __func__, m_pid);
            if (m_server != nullptr) {
                ret = m_server->transact(BINDER_LIB_TEST_GET_STATUS_TRANSACTION, data, &reply);
                EXPECT_EQ(0, ret);
                ret = m_server->transact(BINDER_LIB_TEST_EXIT_TRANSACTION, data, &reply, TF_ONE_WAY);
                EXPECT_EQ(0, ret);
            }
            if (m_serverpid > 0) {
                //printf("wait for %d\n", m_pids[i]);
                pid = wait(&exitStatus);
                EXPECT_EQ(m_serverpid, pid);
                EXPECT_TRUE(WIFEXITED(exitStatus));
                EXPECT_EQ(0, WEXITSTATUS(exitStatus));
            }
        }

        pid_t m_serverpid;
        sp<IBinder> m_server;
};

class BinderLibTest : public ::testing::Test {
    public:
        virtual void SetUp() {
            m_server = static_cast<BinderLibTestEnv *>(binder_env)->getServer();
            IPCThreadState::self()->restoreCallingWorkSource(0); 
        }
        virtual void TearDown() {
        }
    protected:
        sp<IBinder> addServerEtc(int32_t *idPtr, int code)
        {
            int32_t id;
            Parcel data, reply;
            sp<IBinder> binder;

            EXPECT_THAT(m_server->transact(code, data, &reply), StatusEq(NO_ERROR));

            EXPECT_FALSE(binder != nullptr);
            binder = reply.readStrongBinder();
            EXPECT_TRUE(binder != nullptr);
            EXPECT_THAT(reply.readInt32(&id), StatusEq(NO_ERROR));
            if (idPtr)
                *idPtr = id;
            return binder;
        }

        sp<IBinder> addServer(int32_t *idPtr = nullptr)
        {
            return addServerEtc(idPtr, BINDER_LIB_TEST_ADD_SERVER);
        }

        sp<IBinder> addPollServer(int32_t *idPtr = nullptr)
        {
            return addServerEtc(idPtr, BINDER_LIB_TEST_ADD_POLL_SERVER);
        }

        void waitForReadData(int fd, int timeout_ms) {
            int ret;
            pollfd pfd = pollfd();

            pfd.fd = fd;
            pfd.events = POLLIN;
            ret = poll(&pfd, 1, timeout_ms);
            EXPECT_EQ(1, ret);
        }

        sp<IBinder> m_server;
};

class BinderLibTestBundle : public Parcel
{
    public:
        BinderLibTestBundle(void) {}
        explicit BinderLibTestBundle(const Parcel *source) : m_isValid(false) {
            int32_t mark;
            int32_t bundleLen;
            size_t pos;

            if (source->readInt32(&mark))
                return;
            if (mark != MARK_START)
                return;
            if (source->readInt32(&bundleLen))
                return;
            pos = source->dataPosition();
            if (Parcel::appendFrom(source, pos, bundleLen))
                return;
            source->setDataPosition(pos + bundleLen);
            if (source->readInt32(&mark))
                return;
            if (mark != MARK_END)
                return;
            m_isValid = true;
            setDataPosition(0);
        }
        void appendTo(Parcel *dest) {
            dest->writeInt32(MARK_START);
            dest->writeInt32(dataSize());
            dest->appendFrom(this, 0, dataSize());
            dest->writeInt32(MARK_END);
        };
        bool isValid(void) {
            return m_isValid;
        }
    private:
        enum {
            MARK_START  = B_PACK_CHARS('B','T','B','S'),
            MARK_END    = B_PACK_CHARS('B','T','B','E'),
        };
        bool m_isValid;
};

class BinderLibTestEvent
{
    public:
        BinderLibTestEvent(void)
            : m_eventTriggered(false)
        {
            pthread_mutex_init(&m_waitMutex, nullptr);
            pthread_cond_init(&m_waitCond, nullptr);
        }
        int waitEvent(int timeout_s)
        {
            int ret;
            pthread_mutex_lock(&m_waitMutex);
            if (!m_eventTriggered) {
                struct timespec ts;
                clock_gettime(CLOCK_REALTIME, &ts);
                ts.tv_sec += timeout_s;
                pthread_cond_timedwait(&m_waitCond, &m_waitMutex, &ts);
            }
            ret = m_eventTriggered ? NO_ERROR : TIMED_OUT;
            pthread_mutex_unlock(&m_waitMutex);
            return ret;
        }
        pthread_t getTriggeringThread()
        {
            return m_triggeringThread;
        }
    protected:
        void triggerEvent(void) {
            pthread_mutex_lock(&m_waitMutex);
            pthread_cond_signal(&m_waitCond);
            m_eventTriggered = true;
            m_triggeringThread = pthread_self();
            pthread_mutex_unlock(&m_waitMutex);
        };
    private:
        pthread_mutex_t m_waitMutex;
        pthread_cond_t m_waitCond;
        bool m_eventTriggered;
        pthread_t m_triggeringThread;
};

class BinderLibTestCallBack : public BBinder, public BinderLibTestEvent
{
    public:
        BinderLibTestCallBack()
            : m_result(NOT_ENOUGH_DATA)
            , m_prev_end(nullptr)
        {
        }
        status_t getResult(void)
        {
            return m_result;
        }

    private:
        virtual status_t onTransact(uint32_t code,
                                    const Parcel& data, Parcel* reply,
                                    uint32_t flags = 0)
        {
            (void)reply;
            (void)flags;
            switch(code) {
            case BINDER_LIB_TEST_CALL_BACK: {
                status_t status = data.readInt32(&m_result);
                if (status != NO_ERROR) {
                    m_result = status;
                }
                triggerEvent();
                return NO_ERROR;
            }
            case BINDER_LIB_TEST_CALL_BACK_VERIFY_BUF: {
                sp<IBinder> server;
                int ret;
                const uint8_t *buf = data.data();
                size_t size = data.dataSize();
                if (m_prev_end) {
                    /* 64-bit kernel needs at most 8 bytes to align buffer end */
                    EXPECT_LE((size_t)(buf - m_prev_end), (size_t)8);
                } else {
                    EXPECT_TRUE(IsPageAligned((void *)buf));
                }

                m_prev_end = buf + size + data.objectsCount() * sizeof(binder_size_t);

                if (size > 0) {
                    server = static_cast<BinderLibTestEnv *>(binder_env)->getServer();
                    ret = server->transact(BINDER_LIB_TEST_INDIRECT_TRANSACTION,
                                           data, reply);
                    EXPECT_EQ(NO_ERROR, ret);
                }
                return NO_ERROR;
            }
            default:
                return UNKNOWN_TRANSACTION;
            }
        }

        status_t m_result;
        const uint8_t *m_prev_end;
};

class TestDeathRecipient : public IBinder::DeathRecipient, public BinderLibTestEvent
{
    private:
        virtual void binderDied(const wp<IBinder>& who) {
            (void)who;
            triggerEvent();
        };
};

TEST_F(BinderLibTest, NopTransaction) {
    Parcel data, reply;
    EXPECT_THAT(m_server->transact(BINDER_LIB_TEST_NOP_TRANSACTION, data, &reply),
                StatusEq(NO_ERROR));
}

TEST_F(BinderLibTest, NopTransactionOneway) {
    Parcel data, reply;
    EXPECT_THAT(m_server->transact(BINDER_LIB_TEST_NOP_TRANSACTION, data, &reply, TF_ONE_WAY),
                StatusEq(NO_ERROR));
}

TEST_F(BinderLibTest, NopTransactionClear) {
    Parcel data, reply;
    // make sure it accepts the transaction flag
    EXPECT_THAT(m_server->transact(BINDER_LIB_TEST_NOP_TRANSACTION, data, &reply, TF_CLEAR_BUF),
                StatusEq(NO_ERROR));
}

TEST_F(BinderLibTest, Freeze) {
    Parcel data, reply, replypid;
    std::ifstream freezer_file("/sys/fs/cgroup/uid_0/cgroup.freeze");

    // Pass test on devices where the cgroup v2 freezer is not supported
    if (freezer_file.fail()) {
        GTEST_SKIP();
        return;
    }

    EXPECT_THAT(m_server->transact(BINDER_LIB_TEST_GETPID, data, &replypid), StatusEq(NO_ERROR));
    int32_t pid = replypid.readInt32();
    for (int i = 0; i < 10; i++) {
        EXPECT_EQ(NO_ERROR, m_server->transact(BINDER_LIB_TEST_NOP_TRANSACTION_WAIT, data, &reply, TF_ONE_WAY));
    }

    // Pass test on devices where BINDER_FREEZE ioctl is not supported
    int ret = IPCThreadState::self()->freeze(pid, false, 0);
    if (ret != 0) {
        GTEST_SKIP();
        return;
    }

    EXPECT_EQ(-EAGAIN, IPCThreadState::self()->freeze(pid, true, 0));
    EXPECT_EQ(-EAGAIN, IPCThreadState::self()->freeze(pid, true, 0));
    EXPECT_EQ(NO_ERROR, IPCThreadState::self()->freeze(pid, true, 1000));
    EXPECT_EQ(FAILED_TRANSACTION, m_server->transact(BINDER_LIB_TEST_NOP_TRANSACTION, data, &reply));

    bool sync_received, async_received;

    EXPECT_EQ(NO_ERROR, IPCThreadState::self()->getProcessFreezeInfo(pid, &sync_received,
                &async_received));

    EXPECT_EQ(sync_received, 1);
    EXPECT_EQ(async_received, 0);

    uint32_t sync_received2, async_received2;

    EXPECT_EQ(NO_ERROR, IPCThreadState::self()->getProcessFreezeInfo(pid, &sync_received2,
                &async_received2));

    EXPECT_EQ(sync_received2, 1);
    EXPECT_EQ(async_received2, 0);

    EXPECT_EQ(NO_ERROR, IPCThreadState::self()->freeze(pid, 0, 0));
    EXPECT_EQ(NO_ERROR, m_server->transact(BINDER_LIB_TEST_NOP_TRANSACTION, data, &reply));
}

TEST_F(BinderLibTest, SetError) {
    int32_t testValue[] = { 0, -123, 123 };
    for (size_t i = 0; i < ARRAY_SIZE(testValue); i++) {
        Parcel data, reply;
        data.writeInt32(testValue[i]);
        EXPECT_THAT(m_server->transact(BINDER_LIB_TEST_SET_ERROR_TRANSACTION, data, &reply),
                    StatusEq(testValue[i]));
    }
}

TEST_F(BinderLibTest, GetId) {
    int32_t id;
    Parcel data, reply;
    EXPECT_THAT(m_server->transact(BINDER_LIB_TEST_GET_ID_TRANSACTION, data, &reply),
                StatusEq(NO_ERROR));
    EXPECT_THAT(reply.readInt32(&id), StatusEq(NO_ERROR));
    EXPECT_EQ(0, id);
}

TEST_F(BinderLibTest, PtrSize) {
    int32_t ptrsize;
    Parcel data, reply;
    sp<IBinder> server = addServer();
    ASSERT_TRUE(server != nullptr);
    EXPECT_THAT(server->transact(BINDER_LIB_TEST_GET_PTR_SIZE_TRANSACTION, data, &reply),
                StatusEq(NO_ERROR));
    EXPECT_THAT(reply.readInt32(&ptrsize), StatusEq(NO_ERROR));
    RecordProperty("TestPtrSize", sizeof(void *));
    RecordProperty("ServerPtrSize", sizeof(void *));
}

TEST_F(BinderLibTest, IndirectGetId2)
{
    int32_t id;
    int32_t count;
    Parcel data, reply;
    int32_t serverId[3];

    data.writeInt32(ARRAY_SIZE(serverId));
    for (size_t i = 0; i < ARRAY_SIZE(serverId); i++) {
        sp<IBinder> server;
        BinderLibTestBundle datai;

        server = addServer(&serverId[i]);
        ASSERT_TRUE(server != nullptr);
        data.writeStrongBinder(server);
        data.writeInt32(BINDER_LIB_TEST_GET_ID_TRANSACTION);
        datai.appendTo(&data);
    }

    ASSERT_THAT(m_server->transact(BINDER_LIB_TEST_INDIRECT_TRANSACTION, data, &reply),
                StatusEq(NO_ERROR));

    ASSERT_THAT(reply.readInt32(&id), StatusEq(NO_ERROR));
    EXPECT_EQ(0, id);

    ASSERT_THAT(reply.readInt32(&count), StatusEq(NO_ERROR));
    EXPECT_EQ(ARRAY_SIZE(serverId), (size_t)count);

    for (size_t i = 0; i < (size_t)count; i++) {
        BinderLibTestBundle replyi(&reply);
        EXPECT_TRUE(replyi.isValid());
        EXPECT_THAT(replyi.readInt32(&id), StatusEq(NO_ERROR));
        EXPECT_EQ(serverId[i], id);
        EXPECT_EQ(replyi.dataSize(), replyi.dataPosition());
    }

    EXPECT_EQ(reply.dataSize(), reply.dataPosition());
}

TEST_F(BinderLibTest, IndirectGetId3)
{
    int32_t id;
    int32_t count;
    Parcel data, reply;
    int32_t serverId[3];

    data.writeInt32(ARRAY_SIZE(serverId));
    for (size_t i = 0; i < ARRAY_SIZE(serverId); i++) {
        sp<IBinder> server;
        BinderLibTestBundle datai;
        BinderLibTestBundle datai2;

        server = addServer(&serverId[i]);
        ASSERT_TRUE(server != nullptr);
        data.writeStrongBinder(server);
        data.writeInt32(BINDER_LIB_TEST_INDIRECT_TRANSACTION);

        datai.writeInt32(1);
        datai.writeStrongBinder(m_server);
        datai.writeInt32(BINDER_LIB_TEST_GET_ID_TRANSACTION);
        datai2.appendTo(&datai);

        datai.appendTo(&data);
    }

    ASSERT_THAT(m_server->transact(BINDER_LIB_TEST_INDIRECT_TRANSACTION, data, &reply),
                StatusEq(NO_ERROR));

    ASSERT_THAT(reply.readInt32(&id), StatusEq(NO_ERROR));
    EXPECT_EQ(0, id);

    ASSERT_THAT(reply.readInt32(&count), StatusEq(NO_ERROR));
    EXPECT_EQ(ARRAY_SIZE(serverId), (size_t)count);

    for (size_t i = 0; i < (size_t)count; i++) {
        int32_t counti;

        BinderLibTestBundle replyi(&reply);
        EXPECT_TRUE(replyi.isValid());
        EXPECT_THAT(replyi.readInt32(&id), StatusEq(NO_ERROR));
        EXPECT_EQ(serverId[i], id);

        ASSERT_THAT(replyi.readInt32(&counti), StatusEq(NO_ERROR));
        EXPECT_EQ(1, counti);

        BinderLibTestBundle replyi2(&replyi);
        EXPECT_TRUE(replyi2.isValid());
        EXPECT_THAT(replyi2.readInt32(&id), StatusEq(NO_ERROR));
        EXPECT_EQ(0, id);
        EXPECT_EQ(replyi2.dataSize(), replyi2.dataPosition());

        EXPECT_EQ(replyi.dataSize(), replyi.dataPosition());
    }

    EXPECT_EQ(reply.dataSize(), reply.dataPosition());
}

TEST_F(BinderLibTest, CallBack)
{
    Parcel data, reply;
    sp<BinderLibTestCallBack> callBack = new BinderLibTestCallBack();
    data.writeStrongBinder(callBack);
    EXPECT_THAT(m_server->transact(BINDER_LIB_TEST_NOP_CALL_BACK, data, &reply, TF_ONE_WAY),
                StatusEq(NO_ERROR));
    EXPECT_THAT(callBack->waitEvent(5), StatusEq(NO_ERROR));
    EXPECT_THAT(callBack->getResult(), StatusEq(NO_ERROR));
}

TEST_F(BinderLibTest, AddServer)
{
    sp<IBinder> server = addServer();
    ASSERT_TRUE(server != nullptr);
}

TEST_F(BinderLibTest, DeathNotificationStrongRef)
{
    sp<IBinder> sbinder;

    sp<TestDeathRecipient> testDeathRecipient = new TestDeathRecipient();

    {
        sp<IBinder> binder = addServer();
        ASSERT_TRUE(binder != nullptr);
        EXPECT_THAT(binder->linkToDeath(testDeathRecipient), StatusEq(NO_ERROR));
        sbinder = binder;
    }
    {
        Parcel data, reply;
        EXPECT_THAT(sbinder->transact(BINDER_LIB_TEST_EXIT_TRANSACTION, data, &reply, TF_ONE_WAY),
                    StatusEq(OK));
    }
    IPCThreadState::self()->flushCommands();
    EXPECT_THAT(testDeathRecipient->waitEvent(5), StatusEq(NO_ERROR));
    EXPECT_THAT(sbinder->unlinkToDeath(testDeathRecipient), StatusEq(DEAD_OBJECT));
}

TEST_F(BinderLibTest, DeathNotificationMultiple)
{
    status_t ret;
    const int clientcount = 2;
    sp<IBinder> target;
    sp<IBinder> linkedclient[clientcount];
    sp<BinderLibTestCallBack> callBack[clientcount];
    sp<IBinder> passiveclient[clientcount];

    target = addServer();
    ASSERT_TRUE(target != nullptr);
    for (int i = 0; i < clientcount; i++) {
        {
            Parcel data, reply;

            linkedclient[i] = addServer();
            ASSERT_TRUE(linkedclient[i] != nullptr);
            callBack[i] = new BinderLibTestCallBack();
            data.writeStrongBinder(target);
            data.writeStrongBinder(callBack[i]);
            EXPECT_THAT(linkedclient[i]->transact(BINDER_LIB_TEST_LINK_DEATH_TRANSACTION, data,
                                                  &reply, TF_ONE_WAY),
                        StatusEq(NO_ERROR));
        }
        {
            Parcel data, reply;

            passiveclient[i] = addServer();
            ASSERT_TRUE(passiveclient[i] != nullptr);
            data.writeStrongBinder(target);
            EXPECT_THAT(passiveclient[i]->transact(BINDER_LIB_TEST_ADD_STRONG_REF_TRANSACTION, data,
                                                   &reply, TF_ONE_WAY),
                        StatusEq(NO_ERROR));
        }
    }
    {
        Parcel data, reply;
        ret = target->transact(BINDER_LIB_TEST_EXIT_TRANSACTION, data, &reply, TF_ONE_WAY);
        EXPECT_EQ(0, ret);
    }

    for (int i = 0; i < clientcount; i++) {
        EXPECT_THAT(callBack[i]->waitEvent(5), StatusEq(NO_ERROR));
        EXPECT_THAT(callBack[i]->getResult(), StatusEq(NO_ERROR));
    }
}

TEST_F(BinderLibTest, DeathNotificationThread)
{
    status_t ret;
    sp<BinderLibTestCallBack> callback;
    sp<IBinder> target = addServer();
    ASSERT_TRUE(target != nullptr);
    sp<IBinder> client = addServer();
    ASSERT_TRUE(client != nullptr);

    sp<TestDeathRecipient> testDeathRecipient = new TestDeathRecipient();

    EXPECT_THAT(target->linkToDeath(testDeathRecipient), StatusEq(NO_ERROR));

    {
        Parcel data, reply;
        ret = target->transact(BINDER_LIB_TEST_EXIT_TRANSACTION, data, &reply, TF_ONE_WAY);
        EXPECT_EQ(0, ret);
    }

    /* Make sure it's dead */
    testDeathRecipient->waitEvent(5);

    /* Now, pass the ref to another process and ask that process to
     * call linkToDeath() on it, and wait for a response. This tests
     * two things:
     * 1) You still get death notifications when calling linkToDeath()
     *    on a ref that is already dead when it was passed to you.
     * 2) That death notifications are not directly pushed to the thread
     *    registering them, but to the threadpool (proc workqueue) instead.
     *
     * 2) is tested because the thread handling BINDER_LIB_TEST_DEATH_TRANSACTION
     * is blocked on a condition variable waiting for the death notification to be
     * called; therefore, that thread is not available for handling proc work.
     * So, if the death notification was pushed to the thread workqueue, the callback
     * would never be called, and the test would timeout and fail.
     *
     * Note that we can't do this part of the test from this thread itself, because
     * the binder driver would only push death notifications to the thread if
     * it is a looper thread, which this thread is not.
     *
     * See b/23525545 for details.
     */
    {
        Parcel data, reply;

        callback = new BinderLibTestCallBack();
        data.writeStrongBinder(target);
        data.writeStrongBinder(callback);
        EXPECT_THAT(client->transact(BINDER_LIB_TEST_LINK_DEATH_TRANSACTION, data, &reply,
                                     TF_ONE_WAY),
                    StatusEq(NO_ERROR));
    }

    EXPECT_THAT(callback->waitEvent(5), StatusEq(NO_ERROR));
    EXPECT_THAT(callback->getResult(), StatusEq(NO_ERROR));
}

TEST_F(BinderLibTest, PassFile) {
    int ret;
    int pipefd[2];
    uint8_t buf[1] = { 0 };
    uint8_t write_value = 123;

    ret = pipe2(pipefd, O_NONBLOCK);
    ASSERT_EQ(0, ret);

    {
        Parcel data, reply;
        uint8_t writebuf[1] = { write_value };

        EXPECT_THAT(data.writeFileDescriptor(pipefd[1], true), StatusEq(NO_ERROR));

        EXPECT_THAT(data.writeInt32(sizeof(writebuf)), StatusEq(NO_ERROR));

        EXPECT_THAT(data.write(writebuf, sizeof(writebuf)), StatusEq(NO_ERROR));

        EXPECT_THAT(m_server->transact(BINDER_LIB_TEST_WRITE_FILE_TRANSACTION, data, &reply),
                    StatusEq(NO_ERROR));
    }

    ret = read(pipefd[0], buf, sizeof(buf));
    EXPECT_EQ(sizeof(buf), (size_t)ret);
    EXPECT_EQ(write_value, buf[0]);

    waitForReadData(pipefd[0], 5000); /* wait for other proccess to close pipe */

    ret = read(pipefd[0], buf, sizeof(buf));
    EXPECT_EQ(0, ret);

    close(pipefd[0]);
}

TEST_F(BinderLibTest, PassParcelFileDescriptor) {
    const int datasize = 123;
    std::vector<uint8_t> writebuf(datasize);
    for (size_t i = 0; i < writebuf.size(); ++i) {
        writebuf[i] = i;
    }

    android::base::unique_fd read_end, write_end;
    {
        int pipefd[2];
        ASSERT_EQ(0, pipe2(pipefd, O_NONBLOCK));
        read_end.reset(pipefd[0]);
        write_end.reset(pipefd[1]);
    }
    {
        Parcel data;
        EXPECT_EQ(NO_ERROR, data.writeDupParcelFileDescriptor(write_end.get()));
        write_end.reset();
        EXPECT_EQ(NO_ERROR, data.writeInt32(datasize));
        EXPECT_EQ(NO_ERROR, data.write(writebuf.data(), datasize));

        Parcel reply;
        EXPECT_EQ(NO_ERROR,
                  m_server->transact(BINDER_LIB_TEST_WRITE_PARCEL_FILE_DESCRIPTOR_TRANSACTION, data,
                                     &reply));
    }
    std::vector<uint8_t> readbuf(datasize);
    EXPECT_EQ(datasize, read(read_end.get(), readbuf.data(), datasize));
    EXPECT_EQ(writebuf, readbuf);

    waitForReadData(read_end.get(), 5000); /* wait for other proccess to close pipe */

    EXPECT_EQ(0, read(read_end.get(), readbuf.data(), datasize));
}

TEST_F(BinderLibTest, PromoteLocal) {
    sp<IBinder> strong = new BBinder();
    wp<IBinder> weak = strong;
    sp<IBinder> strong_from_weak = weak.promote();
    EXPECT_TRUE(strong != nullptr);
    EXPECT_EQ(strong, strong_from_weak);
    strong = nullptr;
    strong_from_weak = nullptr;
    strong_from_weak = weak.promote();
    EXPECT_TRUE(strong_from_weak == nullptr);
}

TEST_F(BinderLibTest, LocalGetExtension) {
    sp<BBinder> binder = new BBinder();
    sp<IBinder> ext = new BBinder();
    binder->setExtension(ext);
    EXPECT_EQ(ext, binder->getExtension());
}

TEST_F(BinderLibTest, RemoteGetExtension) {
    sp<IBinder> server = addServer();
    ASSERT_TRUE(server != nullptr);

    sp<IBinder> extension;
    EXPECT_EQ(NO_ERROR, server->getExtension(&extension));
    ASSERT_NE(nullptr, extension.get());

    EXPECT_EQ(NO_ERROR, extension->pingBinder());
}

TEST_F(BinderLibTest, CheckHandleZeroBinderHighBitsZeroCookie) {
    Parcel data, reply;

    EXPECT_THAT(m_server->transact(BINDER_LIB_TEST_GET_SELF_TRANSACTION, data, &reply),
                StatusEq(NO_ERROR));

    const flat_binder_object *fb = reply.readObject(false);
    ASSERT_TRUE(fb != nullptr);
    EXPECT_EQ(BINDER_TYPE_HANDLE, fb->hdr.type);
    EXPECT_EQ(m_server, ProcessState::self()->getStrongProxyForHandle(fb->handle));
    EXPECT_EQ((binder_uintptr_t)0, fb->cookie);
    EXPECT_EQ((uint64_t)0, (uint64_t)fb->binder >> 32);
}

TEST_F(BinderLibTest, FreedBinder) {
    status_t ret;

    sp<IBinder> server = addServer();
    ASSERT_TRUE(server != nullptr);

    __u32 freedHandle;
    wp<IBinder> keepFreedBinder;
    {
        Parcel data, reply;
        ASSERT_THAT(server->transact(BINDER_LIB_TEST_CREATE_BINDER_TRANSACTION, data, &reply),
                    StatusEq(NO_ERROR));
        struct flat_binder_object *freed = (struct flat_binder_object *)(reply.data());
        freedHandle = freed->handle;
        /* Add a weak ref to the freed binder so the driver does not
         * delete its reference to it - otherwise the transaction
         * fails regardless of whether the driver is fixed.
         */
        keepFreedBinder = reply.readStrongBinder();
    }
    IPCThreadState::self()->flushCommands();
    {
        Parcel data, reply;
        data.writeStrongBinder(server);
        /* Replace original handle with handle to the freed binder */
        struct flat_binder_object *strong = (struct flat_binder_object *)(data.data());
        __u32 oldHandle = strong->handle;
        strong->handle = freedHandle;
        ret = server->transact(BINDER_LIB_TEST_ADD_STRONG_REF_TRANSACTION, data, &reply);
        /* Returns DEAD_OBJECT (-32) if target crashes and
         * FAILED_TRANSACTION if the driver rejects the invalid
         * object.
         */
        EXPECT_EQ((status_t)FAILED_TRANSACTION, ret);
        /* Restore original handle so parcel destructor does not use
         * the wrong handle.
         */
        strong->handle = oldHandle;
    }
}

TEST_F(BinderLibTest, CheckNoHeaderMappedInUser) {
    Parcel data, reply;
    sp<BinderLibTestCallBack> callBack = new BinderLibTestCallBack();
    for (int i = 0; i < 2; i++) {
        BinderLibTestBundle datai;
        datai.appendFrom(&data, 0, data.dataSize());

        data.freeData();
        data.writeInt32(1);
        data.writeStrongBinder(callBack);
        data.writeInt32(BINDER_LIB_TEST_CALL_BACK_VERIFY_BUF);

        datai.appendTo(&data);
    }
    EXPECT_THAT(m_server->transact(BINDER_LIB_TEST_INDIRECT_TRANSACTION, data, &reply),
                StatusEq(NO_ERROR));
}

TEST_F(BinderLibTest, OnewayQueueing)
{
    Parcel data, data2;

    sp<IBinder> pollServer = addPollServer();

    sp<BinderLibTestCallBack> callBack = new BinderLibTestCallBack();
    data.writeStrongBinder(callBack);
    data.writeInt32(500000); // delay in us before calling back

    sp<BinderLibTestCallBack> callBack2 = new BinderLibTestCallBack();
    data2.writeStrongBinder(callBack2);
    data2.writeInt32(0); // delay in us

    EXPECT_THAT(pollServer->transact(BINDER_LIB_TEST_DELAYED_CALL_BACK, data, nullptr, TF_ONE_WAY),
                StatusEq(NO_ERROR));

    // The delay ensures that this second transaction will end up on the async_todo list
    // (for a single-threaded server)
    EXPECT_THAT(pollServer->transact(BINDER_LIB_TEST_DELAYED_CALL_BACK, data2, nullptr, TF_ONE_WAY),
                StatusEq(NO_ERROR));

    // The server will ensure that the two transactions are handled in the expected order;
    // If the ordering is not as expected, an error will be returned through the callbacks.
    EXPECT_THAT(callBack->waitEvent(2), StatusEq(NO_ERROR));
    EXPECT_THAT(callBack->getResult(), StatusEq(NO_ERROR));

    EXPECT_THAT(callBack2->waitEvent(2), StatusEq(NO_ERROR));
    EXPECT_THAT(callBack2->getResult(), StatusEq(NO_ERROR));
}

TEST_F(BinderLibTest, WorkSourceUnsetByDefault)
{
    status_t ret;
    Parcel data, reply;
    data.writeInterfaceToken(binderLibTestServiceName);
    ret = m_server->transact(BINDER_LIB_TEST_GET_WORK_SOURCE_TRANSACTION, data, &reply);
    EXPECT_EQ(-1, reply.readInt32());
    EXPECT_EQ(NO_ERROR, ret);
}

TEST_F(BinderLibTest, WorkSourceSet)
{
    status_t ret;
    Parcel data, reply;
    IPCThreadState::self()->clearCallingWorkSource();
    int64_t previousWorkSource = IPCThreadState::self()->setCallingWorkSourceUid(100);
    data.writeInterfaceToken(binderLibTestServiceName);
    ret = m_server->transact(BINDER_LIB_TEST_GET_WORK_SOURCE_TRANSACTION, data, &reply);
    EXPECT_EQ(100, reply.readInt32());
    EXPECT_EQ(-1, previousWorkSource);
    EXPECT_EQ(true, IPCThreadState::self()->shouldPropagateWorkSource());
    EXPECT_EQ(NO_ERROR, ret);
}

TEST_F(BinderLibTest, WorkSourceSetWithoutPropagation)
{
    status_t ret;
    Parcel data, reply;

    IPCThreadState::self()->setCallingWorkSourceUidWithoutPropagation(100);
    EXPECT_EQ(false, IPCThreadState::self()->shouldPropagateWorkSource());

    data.writeInterfaceToken(binderLibTestServiceName);
    ret = m_server->transact(BINDER_LIB_TEST_GET_WORK_SOURCE_TRANSACTION, data, &reply);
    EXPECT_EQ(-1, reply.readInt32());
    EXPECT_EQ(false, IPCThreadState::self()->shouldPropagateWorkSource());
    EXPECT_EQ(NO_ERROR, ret);
}

TEST_F(BinderLibTest, WorkSourceCleared)
{
    status_t ret;
    Parcel data, reply;

    IPCThreadState::self()->setCallingWorkSourceUid(100);
    int64_t token = IPCThreadState::self()->clearCallingWorkSource();
    int32_t previousWorkSource = (int32_t)token;
    data.writeInterfaceToken(binderLibTestServiceName);
    ret = m_server->transact(BINDER_LIB_TEST_GET_WORK_SOURCE_TRANSACTION, data, &reply);

    EXPECT_EQ(-1, reply.readInt32());
    EXPECT_EQ(100, previousWorkSource);
    EXPECT_EQ(NO_ERROR, ret);
}

TEST_F(BinderLibTest, WorkSourceRestored)
{
    status_t ret;
    Parcel data, reply;

    IPCThreadState::self()->setCallingWorkSourceUid(100);
    int64_t token = IPCThreadState::self()->clearCallingWorkSource();
    IPCThreadState::self()->restoreCallingWorkSource(token);

    data.writeInterfaceToken(binderLibTestServiceName);
    ret = m_server->transact(BINDER_LIB_TEST_GET_WORK_SOURCE_TRANSACTION, data, &reply);

    EXPECT_EQ(100, reply.readInt32());
    EXPECT_EQ(true, IPCThreadState::self()->shouldPropagateWorkSource());
    EXPECT_EQ(NO_ERROR, ret);
}

TEST_F(BinderLibTest, PropagateFlagSet)
{
    IPCThreadState::self()->clearPropagateWorkSource();
    IPCThreadState::self()->setCallingWorkSourceUid(100);
    EXPECT_EQ(true, IPCThreadState::self()->shouldPropagateWorkSource());
}

TEST_F(BinderLibTest, PropagateFlagCleared)
{
    IPCThreadState::self()->setCallingWorkSourceUid(100);
    IPCThreadState::self()->clearPropagateWorkSource();
    EXPECT_EQ(false, IPCThreadState::self()->shouldPropagateWorkSource());
}

TEST_F(BinderLibTest, PropagateFlagRestored)
{
    int token = IPCThreadState::self()->setCallingWorkSourceUid(100);
    IPCThreadState::self()->restoreCallingWorkSource(token);

    EXPECT_EQ(false, IPCThreadState::self()->shouldPropagateWorkSource());
}

TEST_F(BinderLibTest, WorkSourcePropagatedForAllFollowingBinderCalls)
{
    IPCThreadState::self()->setCallingWorkSourceUid(100);

    Parcel data, reply;
    status_t ret;
    data.writeInterfaceToken(binderLibTestServiceName);
    ret = m_server->transact(BINDER_LIB_TEST_GET_WORK_SOURCE_TRANSACTION, data, &reply);

    Parcel data2, reply2;
    status_t ret2;
    data2.writeInterfaceToken(binderLibTestServiceName);
    ret2 = m_server->transact(BINDER_LIB_TEST_GET_WORK_SOURCE_TRANSACTION, data2, &reply2);
    EXPECT_EQ(100, reply2.readInt32());
    EXPECT_EQ(NO_ERROR, ret2);
}

TEST_F(BinderLibTest, SchedPolicySet) {
    sp<IBinder> server = addServer();
    ASSERT_TRUE(server != nullptr);

    Parcel data, reply;
    EXPECT_THAT(server->transact(BINDER_LIB_TEST_GET_SCHEDULING_POLICY, data, &reply),
                StatusEq(NO_ERROR));

    int policy = reply.readInt32();
    int priority = reply.readInt32();

    EXPECT_EQ(kSchedPolicy, policy & (~SCHED_RESET_ON_FORK));
    EXPECT_EQ(kSchedPriority, priority);
}

TEST_F(BinderLibTest, InheritRt) {
    sp<IBinder> server = addServer();
    ASSERT_TRUE(server != nullptr);

    const struct sched_param param {
        .sched_priority = kSchedPriorityMore,
    };
    EXPECT_EQ(0, sched_setscheduler(getpid(), SCHED_RR, &param));

    Parcel data, reply;
    EXPECT_THAT(server->transact(BINDER_LIB_TEST_GET_SCHEDULING_POLICY, data, &reply),
                StatusEq(NO_ERROR));

    int policy = reply.readInt32();
    int priority = reply.readInt32();

    EXPECT_EQ(kSchedPolicy, policy & (~SCHED_RESET_ON_FORK));
    EXPECT_EQ(kSchedPriorityMore, priority);
}

TEST_F(BinderLibTest, VectorSent) {
    Parcel data, reply;
    sp<IBinder> server = addServer();
    ASSERT_TRUE(server != nullptr);

    std::vector<uint64_t> const testValue = { std::numeric_limits<uint64_t>::max(), 0, 200 };
    data.writeUint64Vector(testValue);

    EXPECT_THAT(server->transact(BINDER_LIB_TEST_ECHO_VECTOR, data, &reply), StatusEq(NO_ERROR));
    std::vector<uint64_t> readValue;
    EXPECT_THAT(reply.readUint64Vector(&readValue), StatusEq(OK));
    EXPECT_EQ(readValue, testValue);
}

TEST_F(BinderLibTest, BufRejected) {
    Parcel data, reply;
    uint32_t buf;
    sp<IBinder> server = addServer();
    ASSERT_TRUE(server != nullptr);

    binder_buffer_object obj {
        .hdr = { .type = BINDER_TYPE_PTR },
        .flags = 0,
        .buffer = reinterpret_cast<binder_uintptr_t>((void*)&buf),
        .length = 4,
    };
    data.setDataCapacity(1024);
    // Write a bogus object at offset 0 to get an entry in the offset table
    data.writeFileDescriptor(0);
    EXPECT_EQ(data.objectsCount(), 1);
    uint8_t *parcelData = const_cast<uint8_t*>(data.data());
    // And now, overwrite it with the buffer object
    memcpy(parcelData, &obj, sizeof(obj));
    data.setDataSize(sizeof(obj));

    // Either the kernel should reject this transaction (if it's correct), but
    // if it's not, the server implementation should return an error if it
    // finds an object in the received Parcel.
    EXPECT_THAT(server->transact(BINDER_LIB_TEST_REJECT_BUF, data, &reply),
                Not(StatusEq(NO_ERROR)));
}

TEST_F(BinderLibTest, GotSid) {
    sp<IBinder> server = addServer();

    Parcel data;
    EXPECT_THAT(server->transact(BINDER_LIB_TEST_CAN_GET_SID, data, nullptr), StatusEq(OK));
}

class BinderLibTestService : public BBinder
{
    public:
        explicit BinderLibTestService(int32_t id)
            : m_id(id)
            , m_nextServerId(id + 1)
            , m_serverStartRequested(false)
            , m_callback(nullptr)
        {
            pthread_mutex_init(&m_serverWaitMutex, nullptr);
            pthread_cond_init(&m_serverWaitCond, nullptr);
        }
        ~BinderLibTestService()
        {
            exit(EXIT_SUCCESS);
        }

        void processPendingCall() {
            if (m_callback != nullptr) {
                Parcel data;
                data.writeInt32(NO_ERROR);
                m_callback->transact(BINDER_LIB_TEST_CALL_BACK, data, nullptr, TF_ONE_WAY);
                m_callback = nullptr;
            }
        }

        virtual status_t onTransact(uint32_t code,
                                    const Parcel& data, Parcel* reply,
                                    uint32_t flags = 0) {
            if (getuid() != (uid_t)IPCThreadState::self()->getCallingUid()) {
                return PERMISSION_DENIED;
            }
            switch (code) {
            case BINDER_LIB_TEST_REGISTER_SERVER: {
                int32_t id;
                sp<IBinder> binder;
                id = data.readInt32();
                binder = data.readStrongBinder();
                if (binder == nullptr) {
                    return BAD_VALUE;
                }

                if (m_id != 0)
                    return INVALID_OPERATION;

                pthread_mutex_lock(&m_serverWaitMutex);
                if (m_serverStartRequested) {
                    m_serverStartRequested = false;
                    m_serverStarted = binder;
                    pthread_cond_signal(&m_serverWaitCond);
                }
                pthread_mutex_unlock(&m_serverWaitMutex);
                return NO_ERROR;
            }
            case BINDER_LIB_TEST_ADD_POLL_SERVER:
            case BINDER_LIB_TEST_ADD_SERVER: {
                int ret;
                int serverid;

                if (m_id != 0) {
                    return INVALID_OPERATION;
                }
                pthread_mutex_lock(&m_serverWaitMutex);
                if (m_serverStartRequested) {
                    ret = -EBUSY;
                } else {
                    serverid = m_nextServerId++;
                    m_serverStartRequested = true;
                    bool usePoll = code == BINDER_LIB_TEST_ADD_POLL_SERVER;

                    pthread_mutex_unlock(&m_serverWaitMutex);
                    ret = start_server_process(serverid, usePoll);
                    pthread_mutex_lock(&m_serverWaitMutex);
                }
                if (ret > 0) {
                    if (m_serverStartRequested) {
                        struct timespec ts;
                        clock_gettime(CLOCK_REALTIME, &ts);
                        ts.tv_sec += 5;
                        ret = pthread_cond_timedwait(&m_serverWaitCond, &m_serverWaitMutex, &ts);
                    }
                    if (m_serverStartRequested) {
                        m_serverStartRequested = false;
                        ret = -ETIMEDOUT;
                    } else {
                        reply->writeStrongBinder(m_serverStarted);
                        reply->writeInt32(serverid);
                        m_serverStarted = nullptr;
                        ret = NO_ERROR;
                    }
                } else if (ret >= 0) {
                    m_serverStartRequested = false;
                    ret = UNKNOWN_ERROR;
                }
                pthread_mutex_unlock(&m_serverWaitMutex);
                return ret;
            }
            case BINDER_LIB_TEST_GETPID:
                reply->writeInt32(getpid());
                return NO_ERROR;
            case BINDER_LIB_TEST_NOP_TRANSACTION_WAIT:
                usleep(5000);
                [[fallthrough]];
            case BINDER_LIB_TEST_NOP_TRANSACTION:
                // oneway error codes should be ignored
                if (flags & TF_ONE_WAY) {
                    return UNKNOWN_ERROR;
                }
                return NO_ERROR;
            case BINDER_LIB_TEST_DELAYED_CALL_BACK: {
                // Note: this transaction is only designed for use with a
                // poll() server. See comments around epoll_wait().
                if (m_callback != nullptr) {
                    // A callback was already pending; this means that
                    // we received a second call while still processing
                    // the first one. Fail the test.
                    sp<IBinder> callback = data.readStrongBinder();
                    Parcel data2;
                    data2.writeInt32(UNKNOWN_ERROR);

                    callback->transact(BINDER_LIB_TEST_CALL_BACK, data2, nullptr, TF_ONE_WAY);
                } else {
                    m_callback = data.readStrongBinder();
                    int32_t delayUs = data.readInt32();
                    /*
                     * It's necessary that we sleep here, so the next
                     * transaction the caller makes will be queued to
                     * the async queue.
                     */
                    usleep(delayUs);

                    /*
                     * Now when we return, libbinder will tell the kernel
                     * we are done with this transaction, and the kernel
                     * can move the queued transaction to either the
                     * thread todo worklist (for kernels without the fix),
                     * or the proc todo worklist. In case of the former,
                     * the next outbound call will pick up the pending
                     * transaction, which leads to undesired reentrant
                     * behavior. This is caught in the if() branch above.
                     */
                }

                return NO_ERROR;
            }
            case BINDER_LIB_TEST_NOP_CALL_BACK: {
                Parcel data2, reply2;
                sp<IBinder> binder;
                binder = data.readStrongBinder();
                if (binder == nullptr) {
                    return BAD_VALUE;
                }
                data2.writeInt32(NO_ERROR);
                binder->transact(BINDER_LIB_TEST_CALL_BACK, data2, &reply2);
                return NO_ERROR;
            }
            case BINDER_LIB_TEST_GET_SELF_TRANSACTION:
                reply->writeStrongBinder(this);
                return NO_ERROR;
            case BINDER_LIB_TEST_GET_ID_TRANSACTION:
                reply->writeInt32(m_id);
                return NO_ERROR;
            case BINDER_LIB_TEST_INDIRECT_TRANSACTION: {
                int32_t count;
                uint32_t indirect_code;
                sp<IBinder> binder;

                count = data.readInt32();
                reply->writeInt32(m_id);
                reply->writeInt32(count);
                for (int i = 0; i < count; i++) {
                    binder = data.readStrongBinder();
                    if (binder == nullptr) {
                        return BAD_VALUE;
                    }
                    indirect_code = data.readInt32();
                    BinderLibTestBundle data2(&data);
                    if (!data2.isValid()) {
                        return BAD_VALUE;
                    }
                    BinderLibTestBundle reply2;
                    binder->transact(indirect_code, data2, &reply2);
                    reply2.appendTo(reply);
                }
                return NO_ERROR;
            }
            case BINDER_LIB_TEST_SET_ERROR_TRANSACTION:
                reply->setError(data.readInt32());
                return NO_ERROR;
            case BINDER_LIB_TEST_GET_PTR_SIZE_TRANSACTION:
                reply->writeInt32(sizeof(void *));
                return NO_ERROR;
            case BINDER_LIB_TEST_GET_STATUS_TRANSACTION:
                return NO_ERROR;
            case BINDER_LIB_TEST_ADD_STRONG_REF_TRANSACTION:
                m_strongRef = data.readStrongBinder();
                return NO_ERROR;
            case BINDER_LIB_TEST_LINK_DEATH_TRANSACTION: {
                int ret;
                Parcel data2, reply2;
                sp<TestDeathRecipient> testDeathRecipient = new TestDeathRecipient();
                sp<IBinder> target;
                sp<IBinder> callback;

                target = data.readStrongBinder();
                if (target == nullptr) {
                    return BAD_VALUE;
                }
                callback = data.readStrongBinder();
                if (callback == nullptr) {
                    return BAD_VALUE;
                }
                ret = target->linkToDeath(testDeathRecipient);
                if (ret == NO_ERROR)
                    ret = testDeathRecipient->waitEvent(5);
                data2.writeInt32(ret);
                callback->transact(BINDER_LIB_TEST_CALL_BACK, data2, &reply2);
                return NO_ERROR;
            }
            case BINDER_LIB_TEST_WRITE_FILE_TRANSACTION: {
                int ret;
                int32_t size;
                const void *buf;
                int fd;

                fd = data.readFileDescriptor();
                if (fd < 0) {
                    return BAD_VALUE;
                }
                ret = data.readInt32(&size);
                if (ret != NO_ERROR) {
                    return ret;
                }
                buf = data.readInplace(size);
                if (buf == nullptr) {
                    return BAD_VALUE;
                }
                ret = write(fd, buf, size);
                if (ret != size)
                    return UNKNOWN_ERROR;
                return NO_ERROR;
            }
            case BINDER_LIB_TEST_WRITE_PARCEL_FILE_DESCRIPTOR_TRANSACTION: {
                int ret;
                int32_t size;
                const void *buf;
                android::base::unique_fd fd;

                ret = data.readUniqueParcelFileDescriptor(&fd);
                if (ret != NO_ERROR) {
                    return ret;
                }
                ret = data.readInt32(&size);
                if (ret != NO_ERROR) {
                    return ret;
                }
                buf = data.readInplace(size);
                if (buf == nullptr) {
                    return BAD_VALUE;
                }
                ret = write(fd.get(), buf, size);
                if (ret != size) return UNKNOWN_ERROR;
                return NO_ERROR;
            }
            case BINDER_LIB_TEST_DELAYED_EXIT_TRANSACTION:
                alarm(10);
                return NO_ERROR;
            case BINDER_LIB_TEST_EXIT_TRANSACTION:
                while (wait(nullptr) != -1 || errno != ECHILD)
                    ;
                exit(EXIT_SUCCESS);
            case BINDER_LIB_TEST_CREATE_BINDER_TRANSACTION: {
                sp<IBinder> binder = new BBinder();
                reply->writeStrongBinder(binder);
                return NO_ERROR;
            }
            case BINDER_LIB_TEST_GET_WORK_SOURCE_TRANSACTION: {
                data.enforceInterface(binderLibTestServiceName);
                reply->writeInt32(IPCThreadState::self()->getCallingWorkSourceUid());
                return NO_ERROR;
            }
            case BINDER_LIB_TEST_GET_SCHEDULING_POLICY: {
                int policy = 0;
                sched_param param;
                if (0 != pthread_getschedparam(pthread_self(), &policy, &param)) {
                    return UNKNOWN_ERROR;
                }
                reply->writeInt32(policy);
                reply->writeInt32(param.sched_priority);
                return NO_ERROR;
            }
            case BINDER_LIB_TEST_ECHO_VECTOR: {
                std::vector<uint64_t> vector;
                auto err = data.readUint64Vector(&vector);
                if (err != NO_ERROR)
                    return err;
                reply->writeUint64Vector(vector);
                return NO_ERROR;
            }
            case BINDER_LIB_TEST_REJECT_BUF: {
                return data.objectsCount() == 0 ? BAD_VALUE : NO_ERROR;
            }
            case BINDER_LIB_TEST_CAN_GET_SID: {
                return IPCThreadState::self()->getCallingSid() == nullptr ? BAD_VALUE : NO_ERROR;
            }
            default:
                return UNKNOWN_TRANSACTION;
            };
        }
    private:
        int32_t m_id;
        int32_t m_nextServerId;
        pthread_mutex_t m_serverWaitMutex;
        pthread_cond_t m_serverWaitCond;
        bool m_serverStartRequested;
        sp<IBinder> m_serverStarted;
        sp<IBinder> m_strongRef;
        sp<IBinder> m_callback;
};

int run_server(int index, int readypipefd, bool usePoll)
{
    binderLibTestServiceName += String16(binderserversuffix);

    status_t ret;
    sp<IServiceManager> sm = defaultServiceManager();
    BinderLibTestService* testServicePtr;
    {
        sp<BinderLibTestService> testService = new BinderLibTestService(index);

        testService->setMinSchedulerPolicy(kSchedPolicy, kSchedPriority);

        testService->setInheritRt(true);

        /*
         * Normally would also contain functionality as well, but we are only
         * testing the extension mechanism.
         */
        testService->setExtension(new BBinder());

        // Required for test "BufRejected'
        testService->setRequestingSid(true);

        /*
         * We need this below, but can't hold a sp<> because it prevents the
         * node from being cleaned up automatically. It's safe in this case
         * because of how the tests are written.
         */
        testServicePtr = testService.get();

        if (index == 0) {
            ret = sm->addService(binderLibTestServiceName, testService);
        } else {
            sp<IBinder> server = sm->getService(binderLibTestServiceName);
            Parcel data, reply;
            data.writeInt32(index);
            data.writeStrongBinder(testService);

            ret = server->transact(BINDER_LIB_TEST_REGISTER_SERVER, data, &reply);
        }
    }
    write(readypipefd, &ret, sizeof(ret));
    close(readypipefd);
    //printf("%s: ret %d\n", __func__, ret);
    if (ret)
        return 1;
    //printf("%s: joinThreadPool\n", __func__);
    if (usePoll) {
        int fd;
        struct epoll_event ev;
        int epoll_fd;
        IPCThreadState::self()->setupPolling(&fd);
        if (fd < 0) {
            return 1;
        }
        IPCThreadState::self()->flushCommands(); // flush BC_ENTER_LOOPER

        epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        if (epoll_fd == -1) {
            return 1;
        }

        ev.events = EPOLLIN;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
            return 1;
        }

        while (1) {
             /*
              * We simulate a single-threaded process using the binder poll
              * interface; besides handling binder commands, it can also
              * issue outgoing transactions, by storing a callback in
              * m_callback.
              *
              * processPendingCall() will then issue that transaction.
              */
             struct epoll_event events[1];
             int numEvents = epoll_wait(epoll_fd, events, 1, 1000);
             if (numEvents < 0) {
                 if (errno == EINTR) {
                     continue;
                 }
                 return 1;
             }
             if (numEvents > 0) {
                 IPCThreadState::self()->handlePolledCommands();
                 IPCThreadState::self()->flushCommands(); // flush BC_FREE_BUFFER
                 testServicePtr->processPendingCall();
             }
        }
    } else {
        ProcessState::self()->startThreadPool();
        IPCThreadState::self()->joinThreadPool();
    }
    //printf("%s: joinThreadPool returned\n", __func__);
    return 1; /* joinThreadPool should not return */
}

int main(int argc, char **argv) {
    ExitIfWrongAbi();

    if (argc == 4 && !strcmp(argv[1], "--servername")) {
        binderservername = argv[2];
    } else {
        binderservername = argv[0];
    }

    if (argc == 6 && !strcmp(argv[1], binderserverarg)) {
        binderserversuffix = argv[5];
        return run_server(atoi(argv[2]), atoi(argv[3]), atoi(argv[4]) == 1);
    }
    binderserversuffix = new char[16];
    snprintf(binderserversuffix, 16, "%d", getpid());
    binderLibTestServiceName += String16(binderserversuffix);

    ::testing::InitGoogleTest(&argc, argv);
    binder_env = AddGlobalTestEnvironment(new BinderLibTestEnv());
    ProcessState::self()->startThreadPool();
    return RUN_ALL_TESTS();
}
