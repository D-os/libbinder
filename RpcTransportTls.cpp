/*
 * Copyright (C) 2021 The Android Open Source Project
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

#define LOG_TAG "RpcTransportTls"
#include <log/log.h>

#include <poll.h>

#include <openssl/bn.h>
#include <openssl/ssl.h>

#include <binder/RpcTransportTls.h>

#include "FdTrigger.h"
#include "RpcState.h"
#include "Utils.h"

#define SHOULD_LOG_TLS_DETAIL false

#if SHOULD_LOG_TLS_DETAIL
#define LOG_TLS_DETAIL(...) ALOGI(__VA_ARGS__)
#else
#define LOG_TLS_DETAIL(...) ALOGV(__VA_ARGS__) // for type checking
#endif

using android::base::ErrnoError;
using android::base::Error;
using android::base::Result;

namespace android {
namespace {

constexpr const int kCertValidDays = 30;

// Implement BIO for socket that ignores SIGPIPE.
int socketNew(BIO* bio) {
    BIO_set_data(bio, reinterpret_cast<void*>(-1));
    BIO_set_init(bio, 0);
    return 1;
}
int socketFree(BIO* bio) {
    LOG_ALWAYS_FATAL_IF(bio == nullptr);
    return 1;
}
int socketRead(BIO* bio, char* buf, int size) {
    android::base::borrowed_fd fd(static_cast<int>(reinterpret_cast<intptr_t>(BIO_get_data(bio))));
    int ret = TEMP_FAILURE_RETRY(::recv(fd.get(), buf, size, MSG_NOSIGNAL));
    BIO_clear_retry_flags(bio);
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        BIO_set_retry_read(bio);
    }
    return ret;
}

int socketWrite(BIO* bio, const char* buf, int size) {
    android::base::borrowed_fd fd(static_cast<int>(reinterpret_cast<intptr_t>(BIO_get_data(bio))));
    int ret = TEMP_FAILURE_RETRY(::send(fd.get(), buf, size, MSG_NOSIGNAL));
    BIO_clear_retry_flags(bio);
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        BIO_set_retry_write(bio);
    }
    return ret;
}

long socketCtrl(BIO* bio, int cmd, long num, void*) { // NOLINT
    android::base::borrowed_fd fd(static_cast<int>(reinterpret_cast<intptr_t>(BIO_get_data(bio))));
    if (cmd == BIO_CTRL_FLUSH) return 1;
    LOG_ALWAYS_FATAL("sockCtrl(fd=%d, %d, %ld)", fd.get(), cmd, num);
    return 0;
}

bssl::UniquePtr<BIO> newSocketBio(android::base::borrowed_fd fd) {
    static const BIO_METHOD* gMethods = ([] {
        auto methods = BIO_meth_new(BIO_get_new_index(), "socket_no_signal");
        LOG_ALWAYS_FATAL_IF(0 == BIO_meth_set_write(methods, socketWrite), "BIO_meth_set_write");
        LOG_ALWAYS_FATAL_IF(0 == BIO_meth_set_read(methods, socketRead), "BIO_meth_set_read");
        LOG_ALWAYS_FATAL_IF(0 == BIO_meth_set_ctrl(methods, socketCtrl), "BIO_meth_set_ctrl");
        LOG_ALWAYS_FATAL_IF(0 == BIO_meth_set_create(methods, socketNew), "BIO_meth_set_create");
        LOG_ALWAYS_FATAL_IF(0 == BIO_meth_set_destroy(methods, socketFree), "BIO_meth_set_destroy");
        return methods;
    })();
    bssl::UniquePtr<BIO> ret(BIO_new(gMethods));
    if (ret == nullptr) return nullptr;
    BIO_set_data(ret.get(), reinterpret_cast<void*>(fd.get()));
    BIO_set_init(ret.get(), 1);
    return ret;
}

bssl::UniquePtr<EVP_PKEY> makeKeyPairForSelfSignedCert() {
    bssl::UniquePtr<EC_KEY> ec_key(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
    if (ec_key == nullptr || !EC_KEY_generate_key(ec_key.get())) {
        ALOGE("Failed to generate key pair.");
        return nullptr;
    }
    bssl::UniquePtr<EVP_PKEY> evp_pkey(EVP_PKEY_new());
    // Use set1 instead of assign to avoid leaking ec_key when assign fails. set1 increments
    // the refcount of the ec_key, so it is okay to release it at the end of this function.
    if (evp_pkey == nullptr || !EVP_PKEY_set1_EC_KEY(evp_pkey.get(), ec_key.get())) {
        ALOGE("Failed to assign key pair.");
        return nullptr;
    }
    return evp_pkey;
}

bssl::UniquePtr<X509> makeSelfSignedCert(EVP_PKEY* evp_pkey, const int valid_days) {
    bssl::UniquePtr<X509> x509(X509_new());
    bssl::UniquePtr<BIGNUM> serial(BN_new());
    bssl::UniquePtr<BIGNUM> serialLimit(BN_new());
    TEST_AND_RETURN(nullptr, BN_lshift(serialLimit.get(), BN_value_one(), 128));
    TEST_AND_RETURN(nullptr, BN_rand_range(serial.get(), serialLimit.get()));
    TEST_AND_RETURN(nullptr, BN_to_ASN1_INTEGER(serial.get(), X509_get_serialNumber(x509.get())));
    TEST_AND_RETURN(nullptr, X509_gmtime_adj(X509_getm_notBefore(x509.get()), 0));
    TEST_AND_RETURN(nullptr,
                    X509_gmtime_adj(X509_getm_notAfter(x509.get()), 60 * 60 * 24 * valid_days));

    X509_NAME* subject = X509_get_subject_name(x509.get());
    TEST_AND_RETURN(nullptr,
                    X509_NAME_add_entry_by_txt(subject, "O", MBSTRING_ASC,
                                               reinterpret_cast<const uint8_t*>("Android"), -1, -1,
                                               0));
    TEST_AND_RETURN(nullptr,
                    X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                                               reinterpret_cast<const uint8_t*>("BinderRPC"), -1,
                                               -1, 0));
    TEST_AND_RETURN(nullptr, X509_set_issuer_name(x509.get(), subject));

    TEST_AND_RETURN(nullptr, X509_set_pubkey(x509.get(), evp_pkey));
    TEST_AND_RETURN(nullptr, X509_sign(x509.get(), evp_pkey, EVP_sha256()));
    return x509;
}

[[maybe_unused]] void sslDebugLog(const SSL* ssl, int type, int value) {
    switch (type) {
        case SSL_CB_HANDSHAKE_START:
            LOG_TLS_DETAIL("Handshake started.");
            break;
        case SSL_CB_HANDSHAKE_DONE:
            LOG_TLS_DETAIL("Handshake done.");
            break;
        case SSL_CB_ACCEPT_LOOP:
            LOG_TLS_DETAIL("Handshake progress: %s", SSL_state_string_long(ssl));
            break;
        default:
            LOG_TLS_DETAIL("SSL Debug Log: type = %d, value = %d", type, value);
            break;
    }
}

// Helper class to ErrorQueue::toString
class ErrorQueueString {
public:
    static std::string toString() {
        ErrorQueueString thiz;
        ERR_print_errors_cb(staticCallback, &thiz);
        return thiz.mSs.str();
    }

private:
    static int staticCallback(const char* str, size_t len, void* ctx) {
        return reinterpret_cast<ErrorQueueString*>(ctx)->callback(str, len);
    }
    int callback(const char* str, size_t len) {
        if (len == 0) return 1; // continue
        // ERR_print_errors_cb place a new line at the end, but it doesn't say so in the API.
        if (str[len - 1] == '\n') len -= 1;
        if (!mIsFirst) {
            mSs << '\n';
        }
        mSs << std::string_view(str, len);
        mIsFirst = false;
        return 1; // continue
    }
    std::stringstream mSs;
    bool mIsFirst = true;
};

// Handles libssl's error queue.
//
// Call into any of its member functions to ensure the error queue is properly handled or cleared.
// If the error queue is not handled or cleared, the destructor will abort.
class ErrorQueue {
public:
    ~ErrorQueue() { LOG_ALWAYS_FATAL_IF(!mHandled); }

    // Clear the error queue.
    void clear() {
        ERR_clear_error();
        mHandled = true;
    }

    // Stores the error queue in |ssl| into a string, then clears the error queue.
    std::string toString() {
        auto ret = ErrorQueueString::toString();
        // Though ERR_print_errors_cb should have cleared it, it is okay to clear again.
        clear();
        return ret;
    }

    // |sslError| should be from Ssl::getError().
    // If |sslError| is WANT_READ / WANT_WRITE, poll for POLLIN / POLLOUT respectively. Otherwise
    // return error. Also return error if |fdTrigger| is triggered before or during poll().
    status_t pollForSslError(android::base::borrowed_fd fd, int sslError, FdTrigger* fdTrigger,
                             const char* fnString, int additionalEvent = 0) {
        switch (sslError) {
            case SSL_ERROR_WANT_READ:
                return handlePoll(POLLIN | additionalEvent, fd, fdTrigger, fnString);
            case SSL_ERROR_WANT_WRITE:
                return handlePoll(POLLOUT | additionalEvent, fd, fdTrigger, fnString);
            case SSL_ERROR_SYSCALL: {
                auto queue = toString();
                LOG_TLS_DETAIL("%s(): %s. Treating as DEAD_OBJECT. Error queue: %s", fnString,
                               SSL_error_description(sslError), queue.c_str());
                return DEAD_OBJECT;
            }
            default: {
                auto queue = toString();
                ALOGE("%s(): %s. Error queue: %s", fnString, SSL_error_description(sslError),
                      queue.c_str());
                return UNKNOWN_ERROR;
            }
        }
    }

private:
    bool mHandled = false;

    status_t handlePoll(int event, android::base::borrowed_fd fd, FdTrigger* fdTrigger,
                        const char* fnString) {
        status_t ret = fdTrigger->triggerablePoll(fd, event);
        if (ret != OK && ret != DEAD_OBJECT && ret != -ECANCELED) {
            ALOGE("triggerablePoll error while poll()-ing after %s(): %s", fnString,
                  statusToString(ret).c_str());
        }
        clear();
        return ret;
    }
};

// Helper to call a function, with its return value instantiable.
template <typename Fn, typename... Args>
struct FuncCaller {
    struct Monostate {};
    static constexpr bool sIsVoid = std::is_void_v<std::invoke_result_t<Fn, Args...>>;
    using Result = std::conditional_t<sIsVoid, Monostate, std::invoke_result_t<Fn, Args...>>;
    static inline Result call(Fn fn, Args&&... args) {
        if constexpr (std::is_void_v<std::invoke_result_t<Fn, Args...>>) {
            std::invoke(fn, std::forward<Args>(args)...);
            return {};
        } else {
            return std::invoke(fn, std::forward<Args>(args)...);
        }
    }
};

// Helper to Ssl::call(). Returns the result to the SSL_* function as well as an ErrorQueue object.
template <typename Fn, typename... Args>
struct SslCaller {
    using RawCaller = FuncCaller<Fn, SSL*, Args...>;
    struct ResultAndErrorQueue {
        typename RawCaller::Result result;
        ErrorQueue errorQueue;
    };
    static inline ResultAndErrorQueue call(Fn fn, SSL* ssl, Args&&... args) {
        LOG_ALWAYS_FATAL_IF(ssl == nullptr);
        auto result = RawCaller::call(fn, std::forward<SSL*>(ssl), std::forward<Args>(args)...);
        return ResultAndErrorQueue{std::move(result), ErrorQueue()};
    }
};

// A wrapper over bssl::UniquePtr<SSL>. This class ensures that all SSL_* functions are called
// through call(), which returns an ErrorQueue object that requires the caller to either handle
// or clear it.
// Example:
//   auto [ret, errorQueue] = ssl.call(SSL_read, buf, size);
//   if (ret >= 0) errorQueue.clear();
//   else ALOGE("%s", errorQueue.toString().c_str());
class Ssl {
public:
    explicit Ssl(bssl::UniquePtr<SSL> ssl) : mSsl(std::move(ssl)) {
        LOG_ALWAYS_FATAL_IF(mSsl == nullptr);
    }

    template <typename Fn, typename... Args>
    inline typename SslCaller<Fn, Args...>::ResultAndErrorQueue call(Fn fn, Args&&... args) {
        return SslCaller<Fn, Args...>::call(fn, mSsl.get(), std::forward<Args>(args)...);
    }

    int getError(int ret) {
        LOG_ALWAYS_FATAL_IF(mSsl == nullptr);
        return SSL_get_error(mSsl.get(), ret);
    }

private:
    bssl::UniquePtr<SSL> mSsl;
};

class RpcTransportTls : public RpcTransport {
public:
    RpcTransportTls(android::base::unique_fd socket, Ssl ssl)
          : mSocket(std::move(socket)), mSsl(std::move(ssl)) {}
    Result<size_t> peek(void* buf, size_t size) override;
    status_t interruptableWriteFully(FdTrigger* fdTrigger, const void* data, size_t size) override;
    status_t interruptableReadFully(FdTrigger* fdTrigger, void* data, size_t size) override;

private:
    android::base::unique_fd mSocket;
    Ssl mSsl;

    static status_t isTriggered(FdTrigger* fdTrigger);
};

// Error code is errno.
Result<size_t> RpcTransportTls::peek(void* buf, size_t size) {
    size_t todo = std::min<size_t>(size, std::numeric_limits<int>::max());
    auto [ret, errorQueue] = mSsl.call(SSL_peek, buf, static_cast<int>(todo));
    if (ret < 0) {
        int err = mSsl.getError(ret);
        if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
            // Seen EAGAIN / EWOULDBLOCK on recv(2) / send(2).
            // Like RpcTransportRaw::peek(), don't handle it here.
            return Error(EWOULDBLOCK) << "SSL_peek(): " << errorQueue.toString();
        }
        return Error() << "SSL_peek(): " << errorQueue.toString();
    }
    errorQueue.clear();
    LOG_TLS_DETAIL("TLS: Peeked %d bytes!", ret);
    return ret;
}

status_t RpcTransportTls::isTriggered(FdTrigger* fdTrigger) {
    auto ret = fdTrigger->isTriggeredPolled();
    if (!ret.ok()) {
        ALOGE("%s: %s", __PRETTY_FUNCTION__, ret.error().message().c_str());
        return ret.error().code() == 0 ? UNKNOWN_ERROR : -ret.error().code();
    }
    return OK;
}

status_t RpcTransportTls::interruptableWriteFully(FdTrigger* fdTrigger, const void* data,
                                                  size_t size) {
    auto buffer = reinterpret_cast<const uint8_t*>(data);
    const uint8_t* end = buffer + size;

    MAYBE_WAIT_IN_FLAKE_MODE;

    // Before doing any I/O, check trigger once. This ensures the trigger is checked at least
    // once. The trigger is also checked via triggerablePoll() after every SSL_write().
    if (status_t status = isTriggered(fdTrigger); status != OK) return status;

    while (buffer < end) {
        size_t todo = std::min<size_t>(end - buffer, std::numeric_limits<int>::max());
        auto [writeSize, errorQueue] = mSsl.call(SSL_write, buffer, todo);
        if (writeSize > 0) {
            buffer += writeSize;
            errorQueue.clear();
            continue;
        }
        // SSL_write() should never return 0 unless BIO_write were to return 0.
        int sslError = mSsl.getError(writeSize);
        // TODO(b/195788248): BIO should contain the FdTrigger, and send(2) / recv(2) should be
        //   triggerablePoll()-ed. Then additionalEvent is no longer necessary.
        status_t pollStatus =
                errorQueue.pollForSslError(mSocket.get(), sslError, fdTrigger, "SSL_write", POLLIN);
        if (pollStatus != OK) return pollStatus;
        // Do not advance buffer. Try SSL_write() again.
    }
    LOG_TLS_DETAIL("TLS: Sent %zu bytes!", size);
    return OK;
}

status_t RpcTransportTls::interruptableReadFully(FdTrigger* fdTrigger, void* data, size_t size) {
    auto buffer = reinterpret_cast<uint8_t*>(data);
    uint8_t* end = buffer + size;

    MAYBE_WAIT_IN_FLAKE_MODE;

    // Before doing any I/O, check trigger once. This ensures the trigger is checked at least
    // once. The trigger is also checked via triggerablePoll() after every SSL_write().
    if (status_t status = isTriggered(fdTrigger); status != OK) return status;

    while (buffer < end) {
        size_t todo = std::min<size_t>(end - buffer, std::numeric_limits<int>::max());
        auto [readSize, errorQueue] = mSsl.call(SSL_read, buffer, todo);
        if (readSize > 0) {
            buffer += readSize;
            errorQueue.clear();
            continue;
        }
        if (readSize == 0) {
            // SSL_read() only returns 0 on EOF.
            errorQueue.clear();
            return DEAD_OBJECT;
        }
        int sslError = mSsl.getError(readSize);
        status_t pollStatus =
                errorQueue.pollForSslError(mSocket.get(), sslError, fdTrigger, "SSL_read");
        if (pollStatus != OK) return pollStatus;
        // Do not advance buffer. Try SSL_read() again.
    }
    LOG_TLS_DETAIL("TLS: Received %zu bytes!", size);
    return OK;
}

// For |ssl|, set internal FD to |fd|, and do handshake. Handshake is triggerable by |fdTrigger|.
bool setFdAndDoHandshake(Ssl* ssl, android::base::borrowed_fd fd, FdTrigger* fdTrigger) {
    bssl::UniquePtr<BIO> bio = newSocketBio(fd);
    TEST_AND_RETURN(false, bio != nullptr);
    auto [_, errorQueue] = ssl->call(SSL_set_bio, bio.get(), bio.get());
    (void)bio.release(); // SSL_set_bio takes ownership.
    errorQueue.clear();

    MAYBE_WAIT_IN_FLAKE_MODE;

    while (true) {
        auto [ret, errorQueue] = ssl->call(SSL_do_handshake);
        if (ret > 0) {
            errorQueue.clear();
            return true;
        }
        if (ret == 0) {
            // SSL_do_handshake() only returns 0 on EOF.
            ALOGE("SSL_do_handshake(): EOF: %s", errorQueue.toString().c_str());
            return false;
        }
        int sslError = ssl->getError(ret);
        status_t pollStatus =
                errorQueue.pollForSslError(fd, sslError, fdTrigger, "SSL_do_handshake");
        if (pollStatus != OK) return false;
    }
}

class RpcTransportCtxTls : public RpcTransportCtx {
public:
    template <typename Impl,
              typename = std::enable_if_t<std::is_base_of_v<RpcTransportCtxTls, Impl>>>
    static std::unique_ptr<RpcTransportCtxTls> create(
            std::shared_ptr<RpcCertificateVerifier> verifier);
    std::unique_ptr<RpcTransport> newTransport(android::base::unique_fd fd,
                                               FdTrigger* fdTrigger) const override;
    std::vector<uint8_t> getCertificate(CertificateFormat) const override;

protected:
    static ssl_verify_result_t sslCustomVerify(SSL* ssl, uint8_t* outAlert);
    virtual void preHandshake(Ssl* ssl) const = 0;
    bssl::UniquePtr<SSL_CTX> mCtx;
    std::shared_ptr<RpcCertificateVerifier> mCertVerifier;
};

std::vector<uint8_t> RpcTransportCtxTls::getCertificate(CertificateFormat) const {
    // TODO(b/195166979): return certificate here
    return {};
}

// Verify by comparing the leaf of peer certificate with every certificate in
// mTrustedPeerCertificates. Does not support certificate chains.
ssl_verify_result_t RpcTransportCtxTls::sslCustomVerify(SSL* ssl, uint8_t* outAlert) {
    LOG_ALWAYS_FATAL_IF(outAlert == nullptr);
    const char* logPrefix = SSL_is_server(ssl) ? "Server" : "Client";

    bssl::UniquePtr<X509> peerCert(SSL_get_peer_certificate(ssl)); // Does not set error queue
    LOG_ALWAYS_FATAL_IF(peerCert == nullptr,
                        "%s: libssl should not ask to verify non-existing cert", logPrefix);

    auto ctx = SSL_get_SSL_CTX(ssl); // Does not set error queue
    LOG_ALWAYS_FATAL_IF(ctx == nullptr);
    // void* -> RpcTransportCtxTls*
    auto rpcTransportCtxTls = reinterpret_cast<RpcTransportCtxTls*>(SSL_CTX_get_app_data(ctx));
    LOG_ALWAYS_FATAL_IF(rpcTransportCtxTls == nullptr);

    status_t verifyStatus = rpcTransportCtxTls->mCertVerifier->verify(peerCert.get(), outAlert);
    if (verifyStatus == OK) {
        return ssl_verify_ok;
    }
    LOG_TLS_DETAIL("%s: Failed to verify client: status = %s, alert = %s", logPrefix,
                   statusToString(verifyStatus).c_str(), SSL_alert_desc_string_long(*outAlert));
    return ssl_verify_invalid;
}

// Common implementation for creating server and client contexts. The child class, |Impl|, is
// provided as a template argument so that this function can initialize an |Impl| object.
template <typename Impl, typename>
std::unique_ptr<RpcTransportCtxTls> RpcTransportCtxTls::create(
        std::shared_ptr<RpcCertificateVerifier> verifier) {
    bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
    TEST_AND_RETURN(nullptr, ctx != nullptr);

    auto evp_pkey = makeKeyPairForSelfSignedCert();
    TEST_AND_RETURN(nullptr, evp_pkey != nullptr);
    auto cert = makeSelfSignedCert(evp_pkey.get(), kCertValidDays);
    TEST_AND_RETURN(nullptr, cert != nullptr);
    TEST_AND_RETURN(nullptr, SSL_CTX_use_PrivateKey(ctx.get(), evp_pkey.get()));
    TEST_AND_RETURN(nullptr, SSL_CTX_use_certificate(ctx.get(), cert.get()));

    // Enable two-way authentication by setting SSL_VERIFY_FAIL_IF_NO_PEER_CERT on server.
    // Client ignores SSL_VERIFY_FAIL_IF_NO_PEER_CERT flag.
    SSL_CTX_set_custom_verify(ctx.get(), SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                              sslCustomVerify);

    // Require at least TLS 1.3
    TEST_AND_RETURN(nullptr, SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION));

    if constexpr (SHOULD_LOG_TLS_DETAIL) { // NOLINT
        SSL_CTX_set_info_callback(ctx.get(), sslDebugLog);
    }

    auto ret = std::make_unique<Impl>();
    // RpcTransportCtxTls* -> void*
    TEST_AND_RETURN(nullptr, SSL_CTX_set_app_data(ctx.get(), reinterpret_cast<void*>(ret.get())));
    ret->mCtx = std::move(ctx);
    ret->mCertVerifier = std::move(verifier);
    return ret;
}

std::unique_ptr<RpcTransport> RpcTransportCtxTls::newTransport(android::base::unique_fd fd,
                                                               FdTrigger* fdTrigger) const {
    bssl::UniquePtr<SSL> ssl(SSL_new(mCtx.get()));
    TEST_AND_RETURN(nullptr, ssl != nullptr);
    Ssl wrapped(std::move(ssl));

    preHandshake(&wrapped);
    TEST_AND_RETURN(nullptr, setFdAndDoHandshake(&wrapped, fd, fdTrigger));
    return std::make_unique<RpcTransportTls>(std::move(fd), std::move(wrapped));
}

class RpcTransportCtxTlsServer : public RpcTransportCtxTls {
protected:
    void preHandshake(Ssl* ssl) const override {
        ssl->call(SSL_set_accept_state).errorQueue.clear();
    }
};

class RpcTransportCtxTlsClient : public RpcTransportCtxTls {
protected:
    void preHandshake(Ssl* ssl) const override {
        ssl->call(SSL_set_connect_state).errorQueue.clear();
    }
};

} // namespace

std::unique_ptr<RpcTransportCtx> RpcTransportCtxFactoryTls::newServerCtx() const {
    return android::RpcTransportCtxTls::create<RpcTransportCtxTlsServer>(mCertVerifier);
}

std::unique_ptr<RpcTransportCtx> RpcTransportCtxFactoryTls::newClientCtx() const {
    return android::RpcTransportCtxTls::create<RpcTransportCtxTlsClient>(mCertVerifier);
}

const char* RpcTransportCtxFactoryTls::toCString() const {
    return "tls";
}

std::unique_ptr<RpcTransportCtxFactory> RpcTransportCtxFactoryTls::make(
        std::shared_ptr<RpcCertificateVerifier> verifier) {
    if (verifier == nullptr) {
        ALOGE("%s: Must provide a certificate verifier", __PRETTY_FUNCTION__);
        return nullptr;
    }
    return std::unique_ptr<RpcTransportCtxFactoryTls>(
            new RpcTransportCtxFactoryTls(std::move(verifier)));
}

} // namespace android
