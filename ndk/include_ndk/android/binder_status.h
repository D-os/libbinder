/*
 * Copyright (C) 2018 The Android Open Source Project
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

/**
 * @addtogroup NdkBinder
 * @{
 */

/**
 * @file binder_status.h
 */

#pragma once

#include <errno.h>
#include <stdint.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

enum {
    STATUS_OK = 0,

    STATUS_UNKNOWN_ERROR = (-2147483647 - 1), // INT32_MIN value
    STATUS_NO_MEMORY = -ENOMEM,
    STATUS_INVALID_OPERATION = -ENOSYS,
    STATUS_BAD_VALUE = -EINVAL,
    STATUS_BAD_TYPE = (STATUS_UNKNOWN_ERROR + 1),
    STATUS_NAME_NOT_FOUND = -ENOENT,
    STATUS_PERMISSION_DENIED = -EPERM,
    STATUS_NO_INIT = -ENODEV,
    STATUS_ALREADY_EXISTS = -EEXIST,
    STATUS_DEAD_OBJECT = -EPIPE,
    STATUS_FAILED_TRANSACTION = (STATUS_UNKNOWN_ERROR + 2),
    STATUS_BAD_INDEX = -EOVERFLOW,
    STATUS_NOT_ENOUGH_DATA = -ENODATA,
    STATUS_WOULD_BLOCK = -EWOULDBLOCK,
    STATUS_TIMED_OUT = -ETIMEDOUT,
    STATUS_UNKNOWN_TRANSACTION = -EBADMSG,
    STATUS_FDS_NOT_ALLOWED = (STATUS_UNKNOWN_ERROR + 7),
    STATUS_UNEXPECTED_NULL = (STATUS_UNKNOWN_ERROR + 8),
};

/**
 * One of the STATUS_* values.
 *
 * All unrecognized values are coerced into STATUS_UNKNOWN_ERROR.
 */
typedef int32_t binder_status_t;

enum {
    EX_NONE = 0,
    EX_SECURITY = -1,
    EX_BAD_PARCELABLE = -2,
    EX_ILLEGAL_ARGUMENT = -3,
    EX_NULL_POINTER = -4,
    EX_ILLEGAL_STATE = -5,
    EX_NETWORK_MAIN_THREAD = -6,
    EX_UNSUPPORTED_OPERATION = -7,
    EX_SERVICE_SPECIFIC = -8,
    EX_PARCELABLE = -9,

    /**
     * This is special, and indicates to native binder proxies that the
     * transaction has failed at a low level.
     */
    EX_TRANSACTION_FAILED = -129,
};

/**
 * One of the EXCEPTION_* types.
 *
 * All unrecognized values are coerced into EXCEPTION_TRANSACTION_FAILED.
 *
 * These exceptions values are used by the SDK for parcelables. Also see Parcel.java.
 */
typedef int32_t binder_exception_t;

/**
 * This is a helper class that encapsulates a standard way to keep track of and chain binder errors
 * along with service specific errors.
 *
 * It is not required to be used in order to parcel/receive transactions, but it is required in
 * order to be compatible with standard AIDL transactions.
 */
struct AStatus;
typedef struct AStatus AStatus;

/**
 * New status which is considered a success.
 */
__attribute__((warn_unused_result)) AStatus* AStatus_newOk();

/**
 * New status with exception code.
 */
__attribute__((warn_unused_result)) AStatus* AStatus_fromExceptionCode(
        binder_exception_t exception);

/**
 * New status with exception code and message.
 */
__attribute__((warn_unused_result)) AStatus* AStatus_fromExceptionCodeWithMessage(
        binder_exception_t exception, const char* message);

/**
 * New status with a service speciic error.
 *
 * This is considered to be EX_TRANSACTION_FAILED with extra information.
 */
__attribute__((warn_unused_result)) AStatus* AStatus_fromServiceSpecificError(
        int32_t serviceSpecific);

/**
 * New status with a service specific error and message.
 *
 * This is considered to be EX_TRANSACTION_FAILED with extra information.
 */
__attribute__((warn_unused_result)) AStatus* AStatus_fromServiceSpecificErrorWithMessage(
        int32_t serviceSpecific, const char* message);

/**
 * New status with binder_status_t. This is typically for low level failures when a binder_status_t
 * is returned by an API on AIBinder or AParcel, and that is to be returned from a method returning
 * an AStatus instance.
 */
__attribute__((warn_unused_result)) AStatus* AStatus_fromStatus(binder_status_t status);

/**
 * Whether this object represents a successful transaction.
 */
bool AStatus_isOk(const AStatus* status);

/**
 * The exception that this status object represents.
 */
binder_exception_t AStatus_getExceptionCode(const AStatus* status);

/**
 * The service specific error if this object represents one. If this object represents a different
 * kind of exception or is ok, this function will return 0. Just because this function returns 0
 * does not mean that the transaction was a success.
 */
int32_t AStatus_getServiceSpecificError(const AStatus* status);

/**
 * The status if this object represents one. If this object represents a different kind of exception
 * or is ok, this function will return 0. Just because this function returns 0 does not mean that
 * the transaction was a success.
 */
binder_status_t AStatus_getStatus(const AStatus* status);

/**
 * If there is a message associated with this status, this will return that message. If there is no
 * message, this will return an empty string.
 *
 * The returned string has the lifetime of the status object passed into this function.
 */
const char* AStatus_getMessage(const AStatus* status);

/**
 * Deletes memory associated with the status instance.
 */
void AStatus_delete(AStatus* status);

__END_DECLS

/** @} */
