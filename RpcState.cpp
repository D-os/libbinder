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

#define LOG_TAG "RpcState"

#include "RpcState.h"

#include <binder/BpBinder.h>
#include <binder/RpcServer.h>

#include "Debug.h"
#include "RpcWireFormat.h"

#include <inttypes.h>

namespace android {

RpcState::RpcState() {}
RpcState::~RpcState() {}

status_t RpcState::onBinderLeaving(const sp<RpcSession>& session, const sp<IBinder>& binder,
                                   RpcAddress* outAddress) {
    bool isRemote = binder->remoteBinder();
    bool isRpc = isRemote && binder->remoteBinder()->isRpcBinder();

    if (isRpc && binder->remoteBinder()->getPrivateAccessorForId().rpcSession() != session) {
        // We need to be able to send instructions over the socket for how to
        // connect to a different server, and we also need to let the host
        // process know that this is happening.
        ALOGE("Cannot send binder from unrelated binder RPC session.");
        return INVALID_OPERATION;
    }

    if (isRemote && !isRpc) {
        // Without additional work, this would have the effect of using this
        // process to proxy calls from the socket over to the other process, and
        // it would make those calls look like they come from us (not over the
        // sockets). In order to make this work transparently like binder, we
        // would instead need to send instructions over the socket for how to
        // connect to the host process, and we also need to let the host process
        // know this was happening.
        ALOGE("Cannot send binder proxy %p over sockets", binder.get());
        return INVALID_OPERATION;
    }

    std::lock_guard<std::mutex> _l(mNodeMutex);

    // TODO(b/182939933): maybe move address out of BpBinder, and keep binder->address map
    // in RpcState
    for (auto& [addr, node] : mNodeForAddress) {
        if (binder == node.binder) {
            if (isRpc) {
                const RpcAddress& actualAddr =
                        binder->remoteBinder()->getPrivateAccessorForId().rpcAddress();
                // TODO(b/182939933): this is only checking integrity of data structure
                // a different data structure doesn't need this
                LOG_ALWAYS_FATAL_IF(addr < actualAddr, "Address mismatch");
                LOG_ALWAYS_FATAL_IF(actualAddr < addr, "Address mismatch");
            }
            node.timesSent++;
            node.sentRef = binder; // might already be set
            *outAddress = addr;
            return OK;
        }
    }
    LOG_ALWAYS_FATAL_IF(isRpc, "RPC binder must have known address at this point");

    auto&& [it, inserted] = mNodeForAddress.insert({RpcAddress::unique(),
                                                    BinderNode{
                                                            .binder = binder,
                                                            .timesSent = 1,
                                                            .sentRef = binder,
                                                    }});
    // TODO(b/182939933): better organization could avoid needing this log
    LOG_ALWAYS_FATAL_IF(!inserted);

    *outAddress = it->first;
    return OK;
}

sp<IBinder> RpcState::onBinderEntering(const sp<RpcSession>& session, const RpcAddress& address) {
    std::unique_lock<std::mutex> _l(mNodeMutex);

    if (auto it = mNodeForAddress.find(address); it != mNodeForAddress.end()) {
        sp<IBinder> binder = it->second.binder.promote();

        // implicitly have strong RPC refcount, since we received this binder
        it->second.timesRecd++;

        _l.unlock();

        // We have timesRecd RPC refcounts, but we only need to hold on to one
        // when we keep the object. All additional dec strongs are sent
        // immediately, we wait to send the last one in BpBinder::onLastDecStrong.
        (void)session->sendDecStrong(address);

        return binder;
    }

    auto&& [it, inserted] = mNodeForAddress.insert({address, BinderNode{}});
    LOG_ALWAYS_FATAL_IF(!inserted, "Failed to insert binder when creating proxy");

    // Currently, all binders are assumed to be part of the same session (no
    // device global binders in the RPC world).
    sp<IBinder> binder = BpBinder::create(session, it->first);
    it->second.binder = binder;
    it->second.timesRecd = 1;
    return binder;
}

size_t RpcState::countBinders() {
    std::lock_guard<std::mutex> _l(mNodeMutex);
    return mNodeForAddress.size();
}

void RpcState::dump() {
    std::lock_guard<std::mutex> _l(mNodeMutex);
    ALOGE("DUMP OF RpcState %p", this);
    ALOGE("DUMP OF RpcState (%zu nodes)", mNodeForAddress.size());
    for (const auto& [address, node] : mNodeForAddress) {
        sp<IBinder> binder = node.binder.promote();

        const char* desc;
        if (binder) {
            if (binder->remoteBinder()) {
                if (binder->remoteBinder()->isRpcBinder()) {
                    desc = "(rpc binder proxy)";
                } else {
                    desc = "(binder proxy)";
                }
            } else {
                desc = "(local binder)";
            }
        } else {
            desc = "(null)";
        }

        ALOGE("- BINDER NODE: %p times sent:%zu times recd: %zu a:%s type:%s",
              node.binder.unsafe_get(), node.timesSent, node.timesRecd, address.toString().c_str(),
              desc);
    }
    ALOGE("END DUMP OF RpcState");
}

void RpcState::terminate() {
    if (SHOULD_LOG_RPC_DETAIL) {
        ALOGE("RpcState::terminate()");
        dump();
    }

    // if the destructor of a binder object makes another RPC call, then calling
    // decStrong could deadlock. So, we must hold onto these binders until
    // mNodeMutex is no longer taken.
    std::vector<sp<IBinder>> tempHoldBinder;

    {
        std::lock_guard<std::mutex> _l(mNodeMutex);
        mTerminated = true;
        for (auto& [address, node] : mNodeForAddress) {
            sp<IBinder> binder = node.binder.promote();
            LOG_ALWAYS_FATAL_IF(binder == nullptr, "Binder %p expected to be owned.", binder.get());

            if (node.sentRef != nullptr) {
                tempHoldBinder.push_back(node.sentRef);
            }
        }

        mNodeForAddress.clear();
    }
}

bool RpcState::rpcSend(const base::unique_fd& fd, const char* what, const void* data, size_t size) {
    LOG_RPC_DETAIL("Sending %s on fd %d: %s", what, fd.get(), hexString(data, size).c_str());

    if (size > std::numeric_limits<ssize_t>::max()) {
        ALOGE("Cannot send %s at size %zu (too big)", what, size);
        terminate();
        return false;
    }

    ssize_t sent = TEMP_FAILURE_RETRY(send(fd.get(), data, size, MSG_NOSIGNAL));

    if (sent < 0 || sent != static_cast<ssize_t>(size)) {
        ALOGE("Failed to send %s (sent %zd of %zu bytes) on fd %d, error: %s", what, sent, size,
              fd.get(), strerror(errno));

        terminate();
        return false;
    }

    return true;
}

bool RpcState::rpcRec(const base::unique_fd& fd, const char* what, void* data, size_t size) {
    if (size > std::numeric_limits<ssize_t>::max()) {
        ALOGE("Cannot rec %s at size %zu (too big)", what, size);
        terminate();
        return false;
    }

    ssize_t recd = TEMP_FAILURE_RETRY(recv(fd.get(), data, size, MSG_WAITALL | MSG_NOSIGNAL));

    if (recd < 0 || recd != static_cast<ssize_t>(size)) {
        terminate();

        if (recd == 0 && errno == 0) {
            LOG_RPC_DETAIL("No more data when trying to read %s on fd %d", what, fd.get());
            return false;
        }

        ALOGE("Failed to read %s (received %zd of %zu bytes) on fd %d, error: %s", what, recd, size,
              fd.get(), strerror(errno));
        return false;
    } else {
        LOG_RPC_DETAIL("Received %s on fd %d: %s", what, fd.get(), hexString(data, size).c_str());
    }

    return true;
}

sp<IBinder> RpcState::getRootObject(const base::unique_fd& fd, const sp<RpcSession>& session) {
    Parcel data;
    data.markForRpc(session);
    Parcel reply;

    status_t status = transact(fd, RpcAddress::zero(), RPC_SPECIAL_TRANSACT_GET_ROOT, data, session,
                               &reply, 0);
    if (status != OK) {
        ALOGE("Error getting root object: %s", statusToString(status).c_str());
        return nullptr;
    }

    return reply.readStrongBinder();
}

status_t RpcState::getMaxThreads(const base::unique_fd& fd, const sp<RpcSession>& session,
                                 size_t* maxThreadsOut) {
    Parcel data;
    data.markForRpc(session);
    Parcel reply;

    status_t status = transact(fd, RpcAddress::zero(), RPC_SPECIAL_TRANSACT_GET_MAX_THREADS, data,
                               session, &reply, 0);
    if (status != OK) {
        ALOGE("Error getting max threads: %s", statusToString(status).c_str());
        return status;
    }

    int32_t maxThreads;
    status = reply.readInt32(&maxThreads);
    if (status != OK) return status;
    if (maxThreads <= 0) {
        ALOGE("Error invalid max maxThreads: %d", maxThreads);
        return BAD_VALUE;
    }

    *maxThreadsOut = maxThreads;
    return OK;
}

status_t RpcState::getSessionId(const base::unique_fd& fd, const sp<RpcSession>& session,
                                int32_t* sessionIdOut) {
    Parcel data;
    data.markForRpc(session);
    Parcel reply;

    status_t status = transact(fd, RpcAddress::zero(), RPC_SPECIAL_TRANSACT_GET_SESSION_ID, data,
                               session, &reply, 0);
    if (status != OK) {
        ALOGE("Error getting session ID: %s", statusToString(status).c_str());
        return status;
    }

    int32_t sessionId;
    status = reply.readInt32(&sessionId);
    if (status != OK) return status;

    *sessionIdOut = sessionId;
    return OK;
}

status_t RpcState::transact(const base::unique_fd& fd, const RpcAddress& address, uint32_t code,
                            const Parcel& data, const sp<RpcSession>& session, Parcel* reply,
                            uint32_t flags) {
    uint64_t asyncNumber = 0;

    if (!address.isZero()) {
        std::lock_guard<std::mutex> _l(mNodeMutex);
        if (mTerminated) return DEAD_OBJECT; // avoid fatal only, otherwise races
        auto it = mNodeForAddress.find(address);
        LOG_ALWAYS_FATAL_IF(it == mNodeForAddress.end(), "Sending transact on unknown address %s",
                            address.toString().c_str());

        if (flags & IBinder::FLAG_ONEWAY) {
            asyncNumber = it->second.asyncNumber++;
        }
    }

    if (!data.isForRpc()) {
        ALOGE("Refusing to send RPC with parcel not crafted for RPC");
        return BAD_TYPE;
    }

    if (data.objectsCount() != 0) {
        ALOGE("Parcel at %p has attached objects but is being used in an RPC call", &data);
        return BAD_TYPE;
    }

    RpcWireTransaction transaction{
            .address = address.viewRawEmbedded(),
            .code = code,
            .flags = flags,
            .asyncNumber = asyncNumber,
    };

    std::vector<uint8_t> transactionData(sizeof(RpcWireTransaction) + data.dataSize());
    memcpy(transactionData.data() + 0, &transaction, sizeof(RpcWireTransaction));
    memcpy(transactionData.data() + sizeof(RpcWireTransaction), data.data(), data.dataSize());

    if (transactionData.size() > std::numeric_limits<uint32_t>::max()) {
        ALOGE("Transaction size too big %zu", transactionData.size());
        return BAD_VALUE;
    }

    RpcWireHeader command{
            .command = RPC_COMMAND_TRANSACT,
            .bodySize = static_cast<uint32_t>(transactionData.size()),
    };

    if (!rpcSend(fd, "transact header", &command, sizeof(command))) {
        return DEAD_OBJECT;
    }
    if (!rpcSend(fd, "command body", transactionData.data(), transactionData.size())) {
        return DEAD_OBJECT;
    }

    if (flags & IBinder::FLAG_ONEWAY) {
        return OK; // do not wait for result
    }

    LOG_ALWAYS_FATAL_IF(reply == nullptr, "Reply parcel must be used for synchronous transaction.");

    return waitForReply(fd, session, reply);
}

static void cleanup_reply_data(Parcel* p, const uint8_t* data, size_t dataSize,
                               const binder_size_t* objects, size_t objectsCount) {
    (void)p;
    delete[] const_cast<uint8_t*>(data - offsetof(RpcWireReply, data));
    (void)dataSize;
    LOG_ALWAYS_FATAL_IF(objects != nullptr);
    LOG_ALWAYS_FATAL_IF(objectsCount, 0);
}

status_t RpcState::waitForReply(const base::unique_fd& fd, const sp<RpcSession>& session,
                                Parcel* reply) {
    RpcWireHeader command;
    while (true) {
        if (!rpcRec(fd, "command header", &command, sizeof(command))) {
            return DEAD_OBJECT;
        }

        if (command.command == RPC_COMMAND_REPLY) break;

        status_t status = processServerCommand(fd, session, command);
        if (status != OK) return status;
    }

    uint8_t* data = new uint8_t[command.bodySize];

    if (!rpcRec(fd, "reply body", data, command.bodySize)) {
        return DEAD_OBJECT;
    }

    if (command.bodySize < sizeof(RpcWireReply)) {
        ALOGE("Expecting %zu but got %" PRId32 " bytes for RpcWireReply. Terminating!",
              sizeof(RpcWireReply), command.bodySize);
        terminate();
        return BAD_VALUE;
    }
    RpcWireReply* rpcReply = reinterpret_cast<RpcWireReply*>(data);
    if (rpcReply->status != OK) return rpcReply->status;

    reply->ipcSetDataReference(rpcReply->data, command.bodySize - offsetof(RpcWireReply, data),
                               nullptr, 0, cleanup_reply_data);

    reply->markForRpc(session);

    return OK;
}

status_t RpcState::sendDecStrong(const base::unique_fd& fd, const RpcAddress& addr) {
    {
        std::lock_guard<std::mutex> _l(mNodeMutex);
        if (mTerminated) return DEAD_OBJECT; // avoid fatal only, otherwise races
        auto it = mNodeForAddress.find(addr);
        LOG_ALWAYS_FATAL_IF(it == mNodeForAddress.end(), "Sending dec strong on unknown address %s",
                            addr.toString().c_str());
        LOG_ALWAYS_FATAL_IF(it->second.timesRecd <= 0, "Bad dec strong %s",
                            addr.toString().c_str());

        it->second.timesRecd--;
        if (it->second.timesRecd == 0 && it->second.timesSent == 0) {
            mNodeForAddress.erase(it);
        }
    }

    RpcWireHeader cmd = {
            .command = RPC_COMMAND_DEC_STRONG,
            .bodySize = sizeof(RpcWireAddress),
    };
    if (!rpcSend(fd, "dec ref header", &cmd, sizeof(cmd))) return DEAD_OBJECT;
    if (!rpcSend(fd, "dec ref body", &addr.viewRawEmbedded(), sizeof(RpcWireAddress)))
        return DEAD_OBJECT;
    return OK;
}

status_t RpcState::getAndExecuteCommand(const base::unique_fd& fd, const sp<RpcSession>& session) {
    LOG_RPC_DETAIL("getAndExecuteCommand on fd %d", fd.get());

    RpcWireHeader command;
    if (!rpcRec(fd, "command header", &command, sizeof(command))) {
        return DEAD_OBJECT;
    }

    return processServerCommand(fd, session, command);
}

status_t RpcState::processServerCommand(const base::unique_fd& fd, const sp<RpcSession>& session,
                                        const RpcWireHeader& command) {
    switch (command.command) {
        case RPC_COMMAND_TRANSACT:
            return processTransact(fd, session, command);
        case RPC_COMMAND_DEC_STRONG:
            return processDecStrong(fd, command);
    }

    // We should always know the version of the opposing side, and since the
    // RPC-binder-level wire protocol is not self synchronizing, we have no way
    // to understand where the current command ends and the next one begins. We
    // also can't consider it a fatal error because this would allow any client
    // to kill us, so ending the session for misbehaving client.
    ALOGE("Unknown RPC command %d - terminating session", command.command);
    terminate();
    return DEAD_OBJECT;
}
status_t RpcState::processTransact(const base::unique_fd& fd, const sp<RpcSession>& session,
                                   const RpcWireHeader& command) {
    LOG_ALWAYS_FATAL_IF(command.command != RPC_COMMAND_TRANSACT, "command: %d", command.command);

    std::vector<uint8_t> transactionData(command.bodySize);
    if (!rpcRec(fd, "transaction body", transactionData.data(), transactionData.size())) {
        return DEAD_OBJECT;
    }

    return processTransactInternal(fd, session, std::move(transactionData));
}

static void do_nothing_to_transact_data(Parcel* p, const uint8_t* data, size_t dataSize,
                                        const binder_size_t* objects, size_t objectsCount) {
    (void)p;
    (void)data;
    (void)dataSize;
    (void)objects;
    (void)objectsCount;
}

status_t RpcState::processTransactInternal(const base::unique_fd& fd, const sp<RpcSession>& session,
                                           std::vector<uint8_t>&& transactionData) {
    if (transactionData.size() < sizeof(RpcWireTransaction)) {
        ALOGE("Expecting %zu but got %zu bytes for RpcWireTransaction. Terminating!",
              sizeof(RpcWireTransaction), transactionData.size());
        terminate();
        return BAD_VALUE;
    }
    RpcWireTransaction* transaction = reinterpret_cast<RpcWireTransaction*>(transactionData.data());

    // TODO(b/182939933): heap allocation just for lookup in mNodeForAddress,
    // maybe add an RpcAddress 'view' if the type remains 'heavy'
    auto addr = RpcAddress::fromRawEmbedded(&transaction->address);

    status_t replyStatus = OK;
    sp<IBinder> target;
    if (!addr.isZero()) {
        std::lock_guard<std::mutex> _l(mNodeMutex);

        auto it = mNodeForAddress.find(addr);
        if (it == mNodeForAddress.end()) {
            ALOGE("Unknown binder address %s.", addr.toString().c_str());
            dump();
            replyStatus = BAD_VALUE;
        } else {
            target = it->second.binder.promote();
            if (target == nullptr) {
                // This can happen if the binder is remote in this process, and
                // another thread has called the last decStrong on this binder.
                // However, for local binders, it indicates a misbehaving client
                // (any binder which is being transacted on should be holding a
                // strong ref count), so in either case, terminating the
                // session.
                ALOGE("While transacting, binder has been deleted at address %s. Terminating!",
                      addr.toString().c_str());
                terminate();
                replyStatus = BAD_VALUE;
            } else if (target->localBinder() == nullptr) {
                ALOGE("Transactions can only go to local binders, not address %s. Terminating!",
                      addr.toString().c_str());
                terminate();
                replyStatus = BAD_VALUE;
            } else if (transaction->flags & IBinder::FLAG_ONEWAY) {
                if (transaction->asyncNumber != it->second.asyncNumber) {
                    // we need to process some other asynchronous transaction
                    // first
                    // TODO(b/183140903): limit enqueues/detect overfill for bad client
                    // TODO(b/183140903): detect when an object is deleted when it still has
                    //        pending async transactions
                    it->second.asyncTodo.push(BinderNode::AsyncTodo{
                            .data = std::move(transactionData),
                            .asyncNumber = transaction->asyncNumber,
                    });
                    LOG_RPC_DETAIL("Enqueuing %" PRId64 " on %s", transaction->asyncNumber,
                                   addr.toString().c_str());
                    return OK;
                }
            }
        }
    }

    Parcel reply;
    reply.markForRpc(session);

    if (replyStatus == OK) {
        Parcel data;
        // transaction->data is owned by this function. Parcel borrows this data and
        // only holds onto it for the duration of this function call. Parcel will be
        // deleted before the 'transactionData' object.
        data.ipcSetDataReference(transaction->data,
                                 transactionData.size() - offsetof(RpcWireTransaction, data),
                                 nullptr /*object*/, 0 /*objectCount*/,
                                 do_nothing_to_transact_data);
        data.markForRpc(session);

        if (target) {
            replyStatus = target->transact(transaction->code, data, &reply, transaction->flags);
        } else {
            LOG_RPC_DETAIL("Got special transaction %u", transaction->code);

            sp<RpcServer> server = session->server().promote();
            if (server) {
                // special case for 'zero' address (special server commands)
                switch (transaction->code) {
                    case RPC_SPECIAL_TRANSACT_GET_ROOT: {
                        replyStatus = reply.writeStrongBinder(server->getRootObject());
                        break;
                    }
                    case RPC_SPECIAL_TRANSACT_GET_MAX_THREADS: {
                        replyStatus = reply.writeInt32(server->getMaxThreads());
                        break;
                    }
                    case RPC_SPECIAL_TRANSACT_GET_SESSION_ID: {
                        // only sessions w/ services can be the source of a
                        // session ID (so still guarded by non-null server)
                        //
                        // sessions associated with servers must have an ID
                        // (hence abort)
                        int32_t id = session->getPrivateAccessorForId().get().value();
                        replyStatus = reply.writeInt32(id);
                        break;
                    }
                    default: {
                        replyStatus = UNKNOWN_TRANSACTION;
                    }
                }
            } else {
                ALOGE("Special command sent, but no server object attached.");
            }
        }
    }

    if (transaction->flags & IBinder::FLAG_ONEWAY) {
        if (replyStatus != OK) {
            ALOGW("Oneway call failed with error: %d", replyStatus);
        }

        LOG_RPC_DETAIL("Processed async transaction %" PRId64 " on %s", transaction->asyncNumber,
                       addr.toString().c_str());

        // Check to see if there is another asynchronous transaction to process.
        // This behavior differs from binder behavior, since in the binder
        // driver, asynchronous transactions will be processed after existing
        // pending binder transactions on the queue. The downside of this is
        // that asynchronous transactions can be drowned out by synchronous
        // transactions. However, we have no easy way to queue these
        // transactions after the synchronous transactions we may want to read
        // from the wire. So, in socket binder here, we have the opposite
        // downside: asynchronous transactions may drown out synchronous
        // transactions.
        {
            std::unique_lock<std::mutex> _l(mNodeMutex);
            auto it = mNodeForAddress.find(addr);
            // last refcount dropped after this transaction happened
            if (it == mNodeForAddress.end()) return OK;

            // note - only updated now, instead of later, so that other threads
            // will queue any later transactions

            // TODO(b/183140903): support > 2**64 async transactions
            //     (we can do this by allowing asyncNumber to wrap, since we
            //     don't expect more than 2**64 simultaneous transactions)
            it->second.asyncNumber++;

            if (it->second.asyncTodo.size() == 0) return OK;
            if (it->second.asyncTodo.top().asyncNumber == it->second.asyncNumber) {
                LOG_RPC_DETAIL("Found next async transaction %" PRId64 " on %s",
                               it->second.asyncNumber, addr.toString().c_str());

                // justification for const_cast (consider avoiding priority_queue):
                // - AsyncTodo operator< doesn't depend on 'data' object
                // - gotta go fast
                std::vector<uint8_t> data = std::move(
                        const_cast<BinderNode::AsyncTodo&>(it->second.asyncTodo.top()).data);
                it->second.asyncTodo.pop();
                _l.unlock();
                return processTransactInternal(fd, session, std::move(data));
            }
        }
        return OK;
    }

    RpcWireReply rpcReply{
            .status = replyStatus,
    };

    std::vector<uint8_t> replyData(sizeof(RpcWireReply) + reply.dataSize());
    memcpy(replyData.data() + 0, &rpcReply, sizeof(RpcWireReply));
    memcpy(replyData.data() + sizeof(RpcWireReply), reply.data(), reply.dataSize());

    if (replyData.size() > std::numeric_limits<uint32_t>::max()) {
        ALOGE("Reply size too big %zu", transactionData.size());
        terminate();
        return BAD_VALUE;
    }

    RpcWireHeader cmdReply{
            .command = RPC_COMMAND_REPLY,
            .bodySize = static_cast<uint32_t>(replyData.size()),
    };

    if (!rpcSend(fd, "reply header", &cmdReply, sizeof(RpcWireHeader))) {
        return DEAD_OBJECT;
    }
    if (!rpcSend(fd, "reply body", replyData.data(), replyData.size())) {
        return DEAD_OBJECT;
    }
    return OK;
}

status_t RpcState::processDecStrong(const base::unique_fd& fd, const RpcWireHeader& command) {
    LOG_ALWAYS_FATAL_IF(command.command != RPC_COMMAND_DEC_STRONG, "command: %d", command.command);

    std::vector<uint8_t> commandData(command.bodySize);
    if (!rpcRec(fd, "dec ref body", commandData.data(), commandData.size())) {
        return DEAD_OBJECT;
    }

    if (command.bodySize < sizeof(RpcWireAddress)) {
        ALOGE("Expecting %zu but got %" PRId32 " bytes for RpcWireAddress. Terminating!",
              sizeof(RpcWireAddress), command.bodySize);
        terminate();
        return BAD_VALUE;
    }
    RpcWireAddress* address = reinterpret_cast<RpcWireAddress*>(commandData.data());

    // TODO(b/182939933): heap allocation just for lookup
    auto addr = RpcAddress::fromRawEmbedded(address);
    std::unique_lock<std::mutex> _l(mNodeMutex);
    auto it = mNodeForAddress.find(addr);
    if (it == mNodeForAddress.end()) {
        ALOGE("Unknown binder address %s for dec strong.", addr.toString().c_str());
        dump();
        return OK;
    }

    sp<IBinder> target = it->second.binder.promote();
    if (target == nullptr) {
        ALOGE("While requesting dec strong, binder has been deleted at address %s. Terminating!",
              addr.toString().c_str());
        terminate();
        return BAD_VALUE;
    }

    if (it->second.timesSent == 0) {
        ALOGE("No record of sending binder, but requested decStrong: %s", addr.toString().c_str());
        return OK;
    }

    LOG_ALWAYS_FATAL_IF(it->second.sentRef == nullptr, "Inconsistent state, lost ref for %s",
                        addr.toString().c_str());

    sp<IBinder> tempHold;

    it->second.timesSent--;
    if (it->second.timesSent == 0) {
        tempHold = it->second.sentRef;
        it->second.sentRef = nullptr;

        if (it->second.timesRecd == 0) {
            mNodeForAddress.erase(it);
        }
    }

    _l.unlock();
    tempHold = nullptr; // destructor may make binder calls on this session

    return OK;
}

} // namespace android
