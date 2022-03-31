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

#include <android-base/hex.h>
#include <android-base/macros.h>
#include <android-base/scopeguard.h>
#include <binder/BpBinder.h>
#include <binder/IPCThreadState.h>
#include <binder/RpcServer.h>

#include "Debug.h"
#include "RpcWireFormat.h"

#include <random>

#include <inttypes.h>

namespace android {

using base::ScopeGuard;

#if RPC_FLAKE_PRONE
void rpcMaybeWaitToFlake() {
    [[clang::no_destroy]] static std::random_device r;
    [[clang::no_destroy]] static std::mutex m;
    unsigned num;
    {
        std::lock_guard<std::mutex> lock(m);
        num = r();
    }
    if (num % 10 == 0) usleep(num % 1000);
}
#endif

RpcState::RpcState() {}
RpcState::~RpcState() {}

status_t RpcState::onBinderLeaving(const sp<RpcSession>& session, const sp<IBinder>& binder,
                                   uint64_t* outAddress) {
    bool isRemote = binder->remoteBinder();
    bool isRpc = isRemote && binder->remoteBinder()->isRpcBinder();

    if (isRpc && binder->remoteBinder()->getPrivateAccessor().rpcSession() != session) {
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
    if (mTerminated) return DEAD_OBJECT;

    // TODO(b/182939933): maybe move address out of BpBinder, and keep binder->address map
    // in RpcState
    for (auto& [addr, node] : mNodeForAddress) {
        if (binder == node.binder) {
            if (isRpc) {
                // check integrity of data structure
                uint64_t actualAddr = binder->remoteBinder()->getPrivateAccessor().rpcAddress();
                LOG_ALWAYS_FATAL_IF(addr != actualAddr, "Address mismatch %" PRIu64 " vs %" PRIu64,
                                    addr, actualAddr);
            }
            node.timesSent++;
            node.sentRef = binder; // might already be set
            *outAddress = addr;
            return OK;
        }
    }
    LOG_ALWAYS_FATAL_IF(isRpc, "RPC binder must have known address at this point");

    bool forServer = session->server() != nullptr;

    // arbitrary limit for maximum number of nodes in a process (otherwise we
    // might run out of addresses)
    if (mNodeForAddress.size() > 100000) {
        return NO_MEMORY;
    }

    while (true) {
        RpcWireAddress address{
                .options = RPC_WIRE_ADDRESS_OPTION_CREATED,
                .address = mNextId,
        };
        if (forServer) {
            address.options |= RPC_WIRE_ADDRESS_OPTION_FOR_SERVER;
        }

        // avoid ubsan abort
        if (mNextId >= std::numeric_limits<uint32_t>::max()) {
            mNextId = 0;
        } else {
            mNextId++;
        }

        auto&& [it, inserted] = mNodeForAddress.insert({RpcWireAddress::toRaw(address),
                                                        BinderNode{
                                                                .binder = binder,
                                                                .sentRef = binder,
                                                                .timesSent = 1,
                                                        }});
        if (inserted) {
            *outAddress = it->first;
            return OK;
        }
    }
}

status_t RpcState::onBinderEntering(const sp<RpcSession>& session, uint64_t address,
                                    sp<IBinder>* out) {
    // ensure that: if we want to use addresses for something else in the future (for
    //   instance, allowing transitive binder sends), that we don't accidentally
    //   send those addresses to old server. Accidentally ignoring this in that
    //   case and considering the binder to be recognized could cause this
    //   process to accidentally proxy transactions for that binder. Of course,
    //   if we communicate with a binder, it could always be proxying
    //   information. However, we want to make sure that isn't done on accident
    //   by a client.
    RpcWireAddress addr = RpcWireAddress::fromRaw(address);
    constexpr uint32_t kKnownOptions =
            RPC_WIRE_ADDRESS_OPTION_CREATED | RPC_WIRE_ADDRESS_OPTION_FOR_SERVER;
    if (addr.options & ~kKnownOptions) {
        ALOGE("Address is of an unknown type, rejecting: %" PRIu64, address);
        return BAD_VALUE;
    }

    std::lock_guard<std::mutex> _l(mNodeMutex);
    if (mTerminated) return DEAD_OBJECT;

    if (auto it = mNodeForAddress.find(address); it != mNodeForAddress.end()) {
        *out = it->second.binder.promote();

        // implicitly have strong RPC refcount, since we received this binder
        it->second.timesRecd++;
        return OK;
    }

    // we don't know about this binder, so the other side of the connection
    // should have created it.
    if ((addr.options & RPC_WIRE_ADDRESS_OPTION_FOR_SERVER) == !!session->server()) {
        ALOGE("Server received unrecognized address which we should own the creation of %" PRIu64,
              address);
        return BAD_VALUE;
    }

    auto&& [it, inserted] = mNodeForAddress.insert({address, BinderNode{}});
    LOG_ALWAYS_FATAL_IF(!inserted, "Failed to insert binder when creating proxy");

    // Currently, all binders are assumed to be part of the same session (no
    // device global binders in the RPC world).
    it->second.binder = *out = BpBinder::PrivateAccessor::create(session, it->first);
    it->second.timesRecd = 1;
    return OK;
}

status_t RpcState::flushExcessBinderRefs(const sp<RpcSession>& session, uint64_t address,
                                         const sp<IBinder>& binder) {
    // We can flush all references when the binder is destroyed. No need to send
    // extra reference counting packets now.
    if (binder->remoteBinder()) return OK;

    std::unique_lock<std::mutex> _l(mNodeMutex);
    if (mTerminated) return DEAD_OBJECT;

    auto it = mNodeForAddress.find(address);

    LOG_ALWAYS_FATAL_IF(it == mNodeForAddress.end(), "Can't be deleted while we hold sp<>");
    LOG_ALWAYS_FATAL_IF(it->second.binder != binder,
                        "Caller of flushExcessBinderRefs using inconsistent arguments");

    LOG_ALWAYS_FATAL_IF(it->second.timesSent <= 0, "Local binder must have been sent %p",
                        binder.get());

    // For a local binder, we only need to know that we sent it. Now that we
    // have an sp<> for this call, we don't need anything more. If the other
    // process is done with this binder, it needs to know we received the
    // refcount associated with this call, so we can acknowledge that we
    // received it. Once (or if) it has no other refcounts, it would reply with
    // its own decStrong so that it could be removed from this session.
    if (it->second.timesRecd != 0) {
        _l.unlock();

        return session->sendDecStrongToTarget(address, 0);
    }

    return OK;
}

size_t RpcState::countBinders() {
    std::lock_guard<std::mutex> _l(mNodeMutex);
    return mNodeForAddress.size();
}

void RpcState::dump() {
    std::lock_guard<std::mutex> _l(mNodeMutex);
    dumpLocked();
}

void RpcState::clear() {
    std::unique_lock<std::mutex> _l(mNodeMutex);

    if (mTerminated) {
        LOG_ALWAYS_FATAL_IF(!mNodeForAddress.empty(),
                            "New state should be impossible after terminating!");
        return;
    }

    if (SHOULD_LOG_RPC_DETAIL) {
        ALOGE("RpcState::clear()");
        dumpLocked();
    }

    // if the destructor of a binder object makes another RPC call, then calling
    // decStrong could deadlock. So, we must hold onto these binders until
    // mNodeMutex is no longer taken.
    std::vector<sp<IBinder>> tempHoldBinder;

    mTerminated = true;
    for (auto& [address, node] : mNodeForAddress) {
        sp<IBinder> binder = node.binder.promote();
        LOG_ALWAYS_FATAL_IF(binder == nullptr, "Binder %p expected to be owned.", binder.get());

        if (node.sentRef != nullptr) {
            tempHoldBinder.push_back(node.sentRef);
        }
    }

    mNodeForAddress.clear();

    _l.unlock();
    tempHoldBinder.clear(); // explicit
}

void RpcState::dumpLocked() {
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

        ALOGE("- BINDER NODE: %p times sent:%zu times recd: %zu a: %" PRIu64 " type: %s",
              node.binder.unsafe_get(), node.timesSent, node.timesRecd, address, desc);
    }
    ALOGE("END DUMP OF RpcState");
}


RpcState::CommandData::CommandData(size_t size) : mSize(size) {
    // The maximum size for regular binder is 1MB for all concurrent
    // transactions. A very small proportion of transactions are even
    // larger than a page, but we need to avoid allocating too much
    // data on behalf of an arbitrary client, or we could risk being in
    // a position where a single additional allocation could run out of
    // memory.
    //
    // Note, this limit may not reflect the total amount of data allocated for a
    // transaction (in some cases, additional fixed size amounts are added),
    // though for rough consistency, we should avoid cases where this data type
    // is used for multiple dynamic allocations for a single transaction.
    constexpr size_t kMaxTransactionAllocation = 100 * 1000;
    if (size == 0) return;
    if (size > kMaxTransactionAllocation) {
        ALOGW("Transaction requested too much data allocation %zu", size);
        return;
    }
    mData.reset(new (std::nothrow) uint8_t[size]);
}

status_t RpcState::rpcSend(const sp<RpcSession::RpcConnection>& connection,
                           const sp<RpcSession>& session, const char* what, iovec* iovs, int niovs,
                           const std::function<status_t()>& altPoll) {
    for (int i = 0; i < niovs; i++) {
        LOG_RPC_DETAIL("Sending %s (part %d of %d) on RpcTransport %p: %s",
                       what, i + 1, niovs, connection->rpcTransport.get(),
                       android::base::HexString(iovs[i].iov_base, iovs[i].iov_len).c_str());
    }

    if (status_t status =
                connection->rpcTransport->interruptableWriteFully(session->mShutdownTrigger.get(),
                                                                  iovs, niovs, altPoll);
        status != OK) {
        LOG_RPC_DETAIL("Failed to write %s (%d iovs) on RpcTransport %p, error: %s", what, niovs,
                       connection->rpcTransport.get(), statusToString(status).c_str());
        (void)session->shutdownAndWait(false);
        return status;
    }

    return OK;
}

status_t RpcState::rpcRec(const sp<RpcSession::RpcConnection>& connection,
                          const sp<RpcSession>& session, const char* what, iovec* iovs, int niovs) {
    if (status_t status =
                connection->rpcTransport->interruptableReadFully(session->mShutdownTrigger.get(),
                                                                 iovs, niovs, {});
        status != OK) {
        LOG_RPC_DETAIL("Failed to read %s (%d iovs) on RpcTransport %p, error: %s", what, niovs,
                       connection->rpcTransport.get(), statusToString(status).c_str());
        (void)session->shutdownAndWait(false);
        return status;
    }

    for (int i = 0; i < niovs; i++) {
        LOG_RPC_DETAIL("Received %s (part %d of %d) on RpcTransport %p: %s",
                       what, i + 1, niovs, connection->rpcTransport.get(),
                       android::base::HexString(iovs[i].iov_base, iovs[i].iov_len).c_str());
    }
    return OK;
}

status_t RpcState::readNewSessionResponse(const sp<RpcSession::RpcConnection>& connection,
                                          const sp<RpcSession>& session, uint32_t* version) {
    RpcNewSessionResponse response;
    iovec iov{&response, sizeof(response)};
    if (status_t status = rpcRec(connection, session, "new session response", &iov, 1);
        status != OK) {
        return status;
    }
    *version = response.version;
    return OK;
}

status_t RpcState::sendConnectionInit(const sp<RpcSession::RpcConnection>& connection,
                                      const sp<RpcSession>& session) {
    RpcOutgoingConnectionInit init{
            .msg = RPC_CONNECTION_INIT_OKAY,
    };
    iovec iov{&init, sizeof(init)};
    return rpcSend(connection, session, "connection init", &iov, 1);
}

status_t RpcState::readConnectionInit(const sp<RpcSession::RpcConnection>& connection,
                                      const sp<RpcSession>& session) {
    RpcOutgoingConnectionInit init;
    iovec iov{&init, sizeof(init)};
    if (status_t status = rpcRec(connection, session, "connection init", &iov, 1); status != OK)
        return status;

    static_assert(sizeof(init.msg) == sizeof(RPC_CONNECTION_INIT_OKAY));
    if (0 != strncmp(init.msg, RPC_CONNECTION_INIT_OKAY, sizeof(init.msg))) {
        ALOGE("Connection init message unrecognized %.*s", static_cast<int>(sizeof(init.msg)),
              init.msg);
        return BAD_VALUE;
    }
    return OK;
}

sp<IBinder> RpcState::getRootObject(const sp<RpcSession::RpcConnection>& connection,
                                    const sp<RpcSession>& session) {
    Parcel data;
    data.markForRpc(session);
    Parcel reply;

    status_t status =
            transactAddress(connection, 0, RPC_SPECIAL_TRANSACT_GET_ROOT, data, session, &reply, 0);
    if (status != OK) {
        ALOGE("Error getting root object: %s", statusToString(status).c_str());
        return nullptr;
    }

    return reply.readStrongBinder();
}

status_t RpcState::getMaxThreads(const sp<RpcSession::RpcConnection>& connection,
                                 const sp<RpcSession>& session, size_t* maxThreadsOut) {
    Parcel data;
    data.markForRpc(session);
    Parcel reply;

    status_t status = transactAddress(connection, 0, RPC_SPECIAL_TRANSACT_GET_MAX_THREADS, data,
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

status_t RpcState::getSessionId(const sp<RpcSession::RpcConnection>& connection,
                                const sp<RpcSession>& session, std::vector<uint8_t>* sessionIdOut) {
    Parcel data;
    data.markForRpc(session);
    Parcel reply;

    status_t status = transactAddress(connection, 0, RPC_SPECIAL_TRANSACT_GET_SESSION_ID, data,
                                      session, &reply, 0);
    if (status != OK) {
        ALOGE("Error getting session ID: %s", statusToString(status).c_str());
        return status;
    }

    return reply.readByteVector(sessionIdOut);
}

status_t RpcState::transact(const sp<RpcSession::RpcConnection>& connection,
                            const sp<IBinder>& binder, uint32_t code, const Parcel& data,
                            const sp<RpcSession>& session, Parcel* reply, uint32_t flags) {
    if (!data.isForRpc()) {
        ALOGE("Refusing to send RPC with parcel not crafted for RPC call on binder %p code "
              "%" PRIu32,
              binder.get(), code);
        return BAD_TYPE;
    }

    if (data.objectsCount() != 0) {
        ALOGE("Parcel at %p has attached objects but is being used in an RPC call on binder %p "
              "code %" PRIu32,
              &data, binder.get(), code);
        return BAD_TYPE;
    }

    uint64_t address;
    if (status_t status = onBinderLeaving(session, binder, &address); status != OK) return status;

    return transactAddress(connection, address, code, data, session, reply, flags);
}

status_t RpcState::transactAddress(const sp<RpcSession::RpcConnection>& connection,
                                   uint64_t address, uint32_t code, const Parcel& data,
                                   const sp<RpcSession>& session, Parcel* reply, uint32_t flags) {
    LOG_ALWAYS_FATAL_IF(!data.isForRpc());
    LOG_ALWAYS_FATAL_IF(data.objectsCount() != 0);

    uint64_t asyncNumber = 0;

    if (address != 0) {
        std::unique_lock<std::mutex> _l(mNodeMutex);
        if (mTerminated) return DEAD_OBJECT; // avoid fatal only, otherwise races
        auto it = mNodeForAddress.find(address);
        LOG_ALWAYS_FATAL_IF(it == mNodeForAddress.end(),
                            "Sending transact on unknown address %" PRIu64, address);

        if (flags & IBinder::FLAG_ONEWAY) {
            asyncNumber = it->second.asyncNumber;
            if (!nodeProgressAsyncNumber(&it->second)) {
                _l.unlock();
                (void)session->shutdownAndWait(false);
                return DEAD_OBJECT;
            }
        }
    }

    LOG_ALWAYS_FATAL_IF(std::numeric_limits<int32_t>::max() - sizeof(RpcWireHeader) -
                                        sizeof(RpcWireTransaction) <
                                data.dataSize(),
                        "Too much data %zu", data.dataSize());

    RpcWireHeader command{
            .command = RPC_COMMAND_TRANSACT,
            .bodySize = static_cast<uint32_t>(sizeof(RpcWireTransaction) + data.dataSize()),
    };

    RpcWireTransaction transaction{
            .address = RpcWireAddress::fromRaw(address),
            .code = code,
            .flags = flags,
            .asyncNumber = asyncNumber,
    };

    constexpr size_t kWaitMaxUs = 1000000;
    constexpr size_t kWaitLogUs = 10000;
    size_t waitUs = 0;

    // Oneway calls have no sync point, so if many are sent before, whether this
    // is a twoway or oneway transaction, they may have filled up the socket.
    // So, make sure we drain them before polling.
    std::function<status_t()> drainRefs = [&] {
        if (waitUs > kWaitLogUs) {
            ALOGE("Cannot send command, trying to process pending refcounts. Waiting %zuus. Too "
                  "many oneway calls?",
                  waitUs);
        }

        if (waitUs > 0) {
            usleep(waitUs);
            waitUs = std::min(kWaitMaxUs, waitUs * 2);
        } else {
            waitUs = 1;
        }

        return drainCommands(connection, session, CommandType::CONTROL_ONLY);
    };

    iovec iovs[]{
            {&command, sizeof(RpcWireHeader)},
            {&transaction, sizeof(RpcWireTransaction)},
            {const_cast<uint8_t*>(data.data()), data.dataSize()},
    };
    if (status_t status =
                rpcSend(connection, session, "transaction", iovs, arraysize(iovs), drainRefs);
        status != OK) {
        // TODO(b/167966510): need to undo onBinderLeaving - we know the
        // refcount isn't successfully transferred.
        return status;
    }

    if (flags & IBinder::FLAG_ONEWAY) {
        LOG_RPC_DETAIL("Oneway command, so no longer waiting on RpcTransport %p",
                       connection->rpcTransport.get());

        // Do not wait on result.
        return OK;
    }

    LOG_ALWAYS_FATAL_IF(reply == nullptr, "Reply parcel must be used for synchronous transaction.");

    return waitForReply(connection, session, reply);
}

static void cleanup_reply_data(Parcel* p, const uint8_t* data, size_t dataSize,
                               const binder_size_t* objects, size_t objectsCount) {
    (void)p;
    delete[] const_cast<uint8_t*>(data - offsetof(RpcWireReply, data));
    (void)dataSize;
    LOG_ALWAYS_FATAL_IF(objects != nullptr);
    LOG_ALWAYS_FATAL_IF(objectsCount != 0, "%zu objects remaining", objectsCount);
}

status_t RpcState::waitForReply(const sp<RpcSession::RpcConnection>& connection,
                                const sp<RpcSession>& session, Parcel* reply) {
    RpcWireHeader command;
    while (true) {
        iovec iov{&command, sizeof(command)};
        if (status_t status = rpcRec(connection, session, "command header (for reply)", &iov, 1);
            status != OK)
            return status;

        if (command.command == RPC_COMMAND_REPLY) break;

        if (status_t status = processCommand(connection, session, command, CommandType::ANY);
            status != OK)
            return status;
    }

    CommandData data(command.bodySize);
    if (!data.valid()) return NO_MEMORY;

    iovec iov{data.data(), command.bodySize};
    if (status_t status = rpcRec(connection, session, "reply body", &iov, 1); status != OK)
        return status;

    if (command.bodySize < sizeof(RpcWireReply)) {
        ALOGE("Expecting %zu but got %" PRId32 " bytes for RpcWireReply. Terminating!",
              sizeof(RpcWireReply), command.bodySize);
        (void)session->shutdownAndWait(false);
        return BAD_VALUE;
    }
    RpcWireReply* rpcReply = reinterpret_cast<RpcWireReply*>(data.data());
    if (rpcReply->status != OK) return rpcReply->status;

    data.release();
    reply->ipcSetDataReference(rpcReply->data, command.bodySize - offsetof(RpcWireReply, data),
                               nullptr, 0, cleanup_reply_data);

    reply->markForRpc(session);

    return OK;
}

status_t RpcState::sendDecStrongToTarget(const sp<RpcSession::RpcConnection>& connection,
                                         const sp<RpcSession>& session, uint64_t addr,
                                         size_t target) {
    RpcDecStrong body = {
            .address = RpcWireAddress::fromRaw(addr),
    };

    {
        std::lock_guard<std::mutex> _l(mNodeMutex);
        if (mTerminated) return DEAD_OBJECT; // avoid fatal only, otherwise races
        auto it = mNodeForAddress.find(addr);
        LOG_ALWAYS_FATAL_IF(it == mNodeForAddress.end(),
                            "Sending dec strong on unknown address %" PRIu64, addr);

        LOG_ALWAYS_FATAL_IF(it->second.timesRecd < target, "Can't dec count of %zu to %zu.",
                            it->second.timesRecd, target);

        // typically this happens when multiple threads send dec refs at the
        // same time - the transactions will get combined automatically
        if (it->second.timesRecd == target) return OK;

        body.amount = it->second.timesRecd - target;
        it->second.timesRecd = target;

        LOG_ALWAYS_FATAL_IF(nullptr != tryEraseNode(it),
                            "Bad state. RpcState shouldn't own received binder");
    }

    RpcWireHeader cmd = {
            .command = RPC_COMMAND_DEC_STRONG,
            .bodySize = sizeof(RpcDecStrong),
    };
    iovec iovs[]{{&cmd, sizeof(cmd)}, {&body, sizeof(body)}};
    return rpcSend(connection, session, "dec ref", iovs, arraysize(iovs));
}

status_t RpcState::getAndExecuteCommand(const sp<RpcSession::RpcConnection>& connection,
                                        const sp<RpcSession>& session, CommandType type) {
    LOG_RPC_DETAIL("getAndExecuteCommand on RpcTransport %p", connection->rpcTransport.get());

    RpcWireHeader command;
    iovec iov{&command, sizeof(command)};
    if (status_t status = rpcRec(connection, session, "command header (for server)", &iov, 1);
        status != OK)
        return status;

    return processCommand(connection, session, command, type);
}

status_t RpcState::drainCommands(const sp<RpcSession::RpcConnection>& connection,
                                 const sp<RpcSession>& session, CommandType type) {
    uint8_t buf;
    while (true) {
        size_t num_bytes;
        status_t status = connection->rpcTransport->peek(&buf, sizeof(buf), &num_bytes);
        if (status == WOULD_BLOCK) break;
        if (status != OK) return status;
        if (!num_bytes) break;

        status = getAndExecuteCommand(connection, session, type);
        if (status != OK) return status;
    }
    return OK;
}

status_t RpcState::processCommand(const sp<RpcSession::RpcConnection>& connection,
                                  const sp<RpcSession>& session, const RpcWireHeader& command,
                                  CommandType type) {
    IPCThreadState* kernelBinderState = IPCThreadState::selfOrNull();
    IPCThreadState::SpGuard spGuard{
            .address = __builtin_frame_address(0),
            .context = "processing binder RPC command",
    };
    const IPCThreadState::SpGuard* origGuard;
    if (kernelBinderState != nullptr) {
        origGuard = kernelBinderState->pushGetCallingSpGuard(&spGuard);
    }
    ScopeGuard guardUnguard = [&]() {
        if (kernelBinderState != nullptr) {
            kernelBinderState->restoreGetCallingSpGuard(origGuard);
        }
    };

    switch (command.command) {
        case RPC_COMMAND_TRANSACT:
            if (type != CommandType::ANY) return BAD_TYPE;
            return processTransact(connection, session, command);
        case RPC_COMMAND_DEC_STRONG:
            return processDecStrong(connection, session, command);
    }

    // We should always know the version of the opposing side, and since the
    // RPC-binder-level wire protocol is not self synchronizing, we have no way
    // to understand where the current command ends and the next one begins. We
    // also can't consider it a fatal error because this would allow any client
    // to kill us, so ending the session for misbehaving client.
    ALOGE("Unknown RPC command %d - terminating session", command.command);
    (void)session->shutdownAndWait(false);
    return DEAD_OBJECT;
}
status_t RpcState::processTransact(const sp<RpcSession::RpcConnection>& connection,
                                   const sp<RpcSession>& session, const RpcWireHeader& command) {
    LOG_ALWAYS_FATAL_IF(command.command != RPC_COMMAND_TRANSACT, "command: %d", command.command);

    CommandData transactionData(command.bodySize);
    if (!transactionData.valid()) {
        return NO_MEMORY;
    }
    iovec iov{transactionData.data(), transactionData.size()};
    if (status_t status = rpcRec(connection, session, "transaction body", &iov, 1); status != OK)
        return status;

    return processTransactInternal(connection, session, std::move(transactionData));
}

static void do_nothing_to_transact_data(Parcel* p, const uint8_t* data, size_t dataSize,
                                        const binder_size_t* objects, size_t objectsCount) {
    (void)p;
    (void)data;
    (void)dataSize;
    (void)objects;
    (void)objectsCount;
}

status_t RpcState::processTransactInternal(const sp<RpcSession::RpcConnection>& connection,
                                           const sp<RpcSession>& session,
                                           CommandData transactionData) {
    // for 'recursive' calls to this, we have already read and processed the
    // binder from the transaction data and taken reference counts into account,
    // so it is cached here.
    sp<IBinder> target;
processTransactInternalTailCall:

    if (transactionData.size() < sizeof(RpcWireTransaction)) {
        ALOGE("Expecting %zu but got %zu bytes for RpcWireTransaction. Terminating!",
              sizeof(RpcWireTransaction), transactionData.size());
        (void)session->shutdownAndWait(false);
        return BAD_VALUE;
    }
    RpcWireTransaction* transaction = reinterpret_cast<RpcWireTransaction*>(transactionData.data());

    uint64_t addr = RpcWireAddress::toRaw(transaction->address);
    bool oneway = transaction->flags & IBinder::FLAG_ONEWAY;

    status_t replyStatus = OK;
    if (addr != 0) {
        if (!target) {
            replyStatus = onBinderEntering(session, addr, &target);
        }

        if (replyStatus != OK) {
            // do nothing
        } else if (target == nullptr) {
            // This can happen if the binder is remote in this process, and
            // another thread has called the last decStrong on this binder.
            // However, for local binders, it indicates a misbehaving client
            // (any binder which is being transacted on should be holding a
            // strong ref count), so in either case, terminating the
            // session.
            ALOGE("While transacting, binder has been deleted at address %" PRIu64 ". Terminating!",
                  addr);
            (void)session->shutdownAndWait(false);
            replyStatus = BAD_VALUE;
        } else if (target->localBinder() == nullptr) {
            ALOGE("Unknown binder address or non-local binder, not address %" PRIu64
                  ". Terminating!",
                  addr);
            (void)session->shutdownAndWait(false);
            replyStatus = BAD_VALUE;
        } else if (oneway) {
            std::unique_lock<std::mutex> _l(mNodeMutex);
            auto it = mNodeForAddress.find(addr);
            if (it->second.binder.promote() != target) {
                ALOGE("Binder became invalid during transaction. Bad client? %" PRIu64, addr);
                replyStatus = BAD_VALUE;
            } else if (transaction->asyncNumber != it->second.asyncNumber) {
                // we need to process some other asynchronous transaction
                // first
                it->second.asyncTodo.push(BinderNode::AsyncTodo{
                        .ref = target,
                        .data = std::move(transactionData),
                        .asyncNumber = transaction->asyncNumber,
                });

                size_t numPending = it->second.asyncTodo.size();
                LOG_RPC_DETAIL("Enqueuing %" PRIu64 " on %" PRIu64 " (%zu pending)",
                               transaction->asyncNumber, addr, numPending);

                constexpr size_t kArbitraryOnewayCallTerminateLevel = 10000;
                constexpr size_t kArbitraryOnewayCallWarnLevel = 1000;
                constexpr size_t kArbitraryOnewayCallWarnPer = 1000;

                if (numPending >= kArbitraryOnewayCallWarnLevel) {
                    if (numPending >= kArbitraryOnewayCallTerminateLevel) {
                        ALOGE("WARNING: %zu pending oneway transactions. Terminating!", numPending);
                        _l.unlock();
                        (void)session->shutdownAndWait(false);
                        return FAILED_TRANSACTION;
                    }

                    if (numPending % kArbitraryOnewayCallWarnPer == 0) {
                        ALOGW("Warning: many oneway transactions built up on %p (%zu)",
                              target.get(), numPending);
                    }
                }
                return OK;
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
            bool origAllowNested = connection->allowNested;
            connection->allowNested = !oneway;

            replyStatus = target->transact(transaction->code, data, &reply, transaction->flags);

            connection->allowNested = origAllowNested;
        } else {
            LOG_RPC_DETAIL("Got special transaction %u", transaction->code);

            switch (transaction->code) {
                case RPC_SPECIAL_TRANSACT_GET_MAX_THREADS: {
                    replyStatus = reply.writeInt32(session->getMaxIncomingThreads());
                    break;
                }
                case RPC_SPECIAL_TRANSACT_GET_SESSION_ID: {
                    // for client connections, this should always report the value
                    // originally returned from the server, so this is asserting
                    // that it exists
                    replyStatus = reply.writeByteVector(session->mId);
                    break;
                }
                default: {
                    sp<RpcServer> server = session->server();
                    if (server) {
                        switch (transaction->code) {
                            case RPC_SPECIAL_TRANSACT_GET_ROOT: {
                                sp<IBinder> root = session->mSessionSpecificRootObject
                                        ?: server->getRootObject();
                                replyStatus = reply.writeStrongBinder(root);
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
        }
    }

    if (oneway) {
        if (replyStatus != OK) {
            ALOGW("Oneway call failed with error: %d", replyStatus);
        }

        LOG_RPC_DETAIL("Processed async transaction %" PRIu64 " on %" PRIu64,
                       transaction->asyncNumber, addr);

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

            if (!nodeProgressAsyncNumber(&it->second)) {
                _l.unlock();
                (void)session->shutdownAndWait(false);
                return DEAD_OBJECT;
            }

            if (it->second.asyncTodo.size() == 0) return OK;
            if (it->second.asyncTodo.top().asyncNumber == it->second.asyncNumber) {
                LOG_RPC_DETAIL("Found next async transaction %" PRIu64 " on %" PRIu64,
                               it->second.asyncNumber, addr);

                // justification for const_cast (consider avoiding priority_queue):
                // - AsyncTodo operator< doesn't depend on 'data' or 'ref' objects
                // - gotta go fast
                auto& todo = const_cast<BinderNode::AsyncTodo&>(it->second.asyncTodo.top());

                // reset up arguments
                transactionData = std::move(todo.data);
                LOG_ALWAYS_FATAL_IF(target != todo.ref,
                                    "async list should be associated with a binder");

                it->second.asyncTodo.pop();
                goto processTransactInternalTailCall;
            }
        }

        // done processing all the async commands on this binder that we can, so
        // write decstrongs on the binder
        if (addr != 0 && replyStatus == OK) {
            return flushExcessBinderRefs(session, addr, target);
        }

        return OK;
    }

    // Binder refs are flushed for oneway calls only after all calls which are
    // built up are executed. Otherwise, they fill up the binder buffer.
    if (addr != 0 && replyStatus == OK) {
        replyStatus = flushExcessBinderRefs(session, addr, target);
    }

    LOG_ALWAYS_FATAL_IF(std::numeric_limits<int32_t>::max() - sizeof(RpcWireHeader) -
                                        sizeof(RpcWireReply) <
                                reply.dataSize(),
                        "Too much data for reply %zu", reply.dataSize());

    RpcWireHeader cmdReply{
            .command = RPC_COMMAND_REPLY,
            .bodySize = static_cast<uint32_t>(sizeof(RpcWireReply) + reply.dataSize()),
    };
    RpcWireReply rpcReply{
            .status = replyStatus,
    };

    iovec iovs[]{
            {&cmdReply, sizeof(RpcWireHeader)},
            {&rpcReply, sizeof(RpcWireReply)},
            {const_cast<uint8_t*>(reply.data()), reply.dataSize()},
    };
    return rpcSend(connection, session, "reply", iovs, arraysize(iovs));
}

status_t RpcState::processDecStrong(const sp<RpcSession::RpcConnection>& connection,
                                    const sp<RpcSession>& session, const RpcWireHeader& command) {
    LOG_ALWAYS_FATAL_IF(command.command != RPC_COMMAND_DEC_STRONG, "command: %d", command.command);

    CommandData commandData(command.bodySize);
    if (!commandData.valid()) {
        return NO_MEMORY;
    }
    iovec iov{commandData.data(), commandData.size()};
    if (status_t status = rpcRec(connection, session, "dec ref body", &iov, 1); status != OK)
        return status;

    if (command.bodySize != sizeof(RpcDecStrong)) {
        ALOGE("Expecting %zu but got %" PRId32 " bytes for RpcDecStrong. Terminating!",
              sizeof(RpcDecStrong), command.bodySize);
        (void)session->shutdownAndWait(false);
        return BAD_VALUE;
    }
    RpcDecStrong* body = reinterpret_cast<RpcDecStrong*>(commandData.data());

    uint64_t addr = RpcWireAddress::toRaw(body->address);
    std::unique_lock<std::mutex> _l(mNodeMutex);
    auto it = mNodeForAddress.find(addr);
    if (it == mNodeForAddress.end()) {
        ALOGE("Unknown binder address %" PRIu64 " for dec strong.", addr);
        return OK;
    }

    sp<IBinder> target = it->second.binder.promote();
    if (target == nullptr) {
        ALOGE("While requesting dec strong, binder has been deleted at address %" PRIu64
              ". Terminating!",
              addr);
        _l.unlock();
        (void)session->shutdownAndWait(false);
        return BAD_VALUE;
    }

    if (it->second.timesSent < body->amount) {
        ALOGE("Record of sending binder %zu times, but requested decStrong for %" PRIu64 " of %u",
              it->second.timesSent, addr, body->amount);
        return OK;
    }

    LOG_ALWAYS_FATAL_IF(it->second.sentRef == nullptr, "Inconsistent state, lost ref for %" PRIu64,
                        addr);

    LOG_RPC_DETAIL("Processing dec strong of %" PRIu64 " by %u from %zu", addr, body->amount,
                   it->second.timesSent);

    it->second.timesSent -= body->amount;
    sp<IBinder> tempHold = tryEraseNode(it);
    _l.unlock();
    tempHold = nullptr; // destructor may make binder calls on this session

    return OK;
}

sp<IBinder> RpcState::tryEraseNode(std::map<uint64_t, BinderNode>::iterator& it) {
    sp<IBinder> ref;

    if (it->second.timesSent == 0) {
        ref = std::move(it->second.sentRef);

        if (it->second.timesRecd == 0) {
            LOG_ALWAYS_FATAL_IF(!it->second.asyncTodo.empty(),
                                "Can't delete binder w/ pending async transactions");
            mNodeForAddress.erase(it);
        }
    }

    return ref;
}

bool RpcState::nodeProgressAsyncNumber(BinderNode* node) {
    // 2**64 =~ 10**19 =~ 1000 transactions per second for 585 million years to
    // a single binder
    if (node->asyncNumber >= std::numeric_limits<decltype(node->asyncNumber)>::max()) {
        ALOGE("Out of async transaction IDs. Terminating");
        return false;
    }
    node->asyncNumber++;
    return true;
}

} // namespace android
