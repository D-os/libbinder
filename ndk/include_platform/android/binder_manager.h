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

#pragma once

#include <android/binder_ibinder.h>
#include <android/binder_status.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

/**
 * This registers the service with the default service manager under this instance name. This does
 * not take ownership of binder.
 *
 * \param binder object to register globally with the service manager.
 * \param instance identifier of the service. This will be used to lookup the service.
 *
 * \return EX_NONE on success.
 */
__attribute__((warn_unused_result)) binder_exception_t AServiceManager_addService(
        AIBinder* binder, const char* instance);

/**
 * Gets a binder object with this specific instance name. Will return nullptr immediately if the
 * service is not available This also implicitly calls AIBinder_incStrong (so the caller of this
 * function is responsible for calling AIBinder_decStrong).
 *
 * \param instance identifier of the service used to lookup the service.
 */
__attribute__((warn_unused_result)) AIBinder* AServiceManager_checkService(const char* instance);

/**
 * Gets a binder object with this specific instance name. Blocks for a couple of seconds waiting on
 * it. This also implicitly calls AIBinder_incStrong (so the caller of this function is responsible
 * for calling AIBinder_decStrong).
 *
 * \param instance identifier of the service used to lookup the service.
 */
__attribute__((warn_unused_result)) AIBinder* AServiceManager_getService(const char* instance);

/**
 * Registers a lazy service with the default service manager under the 'instance' name.
 * Does not take ownership of binder.
 * The service must be configured statically with init so it can be restarted with
 * ctl.interface.* messages from servicemanager.
 * AServiceManager_registerLazyService cannot safely be used with AServiceManager_addService
 * in the same process. If one service is registered with AServiceManager_registerLazyService,
 * the entire process will have its lifetime controlled by servicemanager.
 * Instead, all services in the process should be registered using
 * AServiceManager_registerLazyService.
 *
 * \param binder object to register globally with the service manager.
 * \param instance identifier of the service. This will be used to lookup the service.
 *
 * \return STATUS_OK on success.
 */
binder_status_t AServiceManager_registerLazyService(AIBinder* binder, const char* instance)
        __INTRODUCED_IN(31);

/**
 * Gets a binder object with this specific instance name. Efficiently waits for the service.
 * If the service is not declared, it will wait indefinitely. Requires the threadpool
 * to be started in the service.
 * This also implicitly calls AIBinder_incStrong (so the caller of this function is responsible
 * for calling AIBinder_decStrong).
 *
 * \param instance identifier of the service used to lookup the service.
 *
 * \return service if registered, null if not.
 */
__attribute__((warn_unused_result)) AIBinder* AServiceManager_waitForService(const char* instance)
        __INTRODUCED_IN(31);

/**
 * Check if a service is declared (e.g. VINTF manifest).
 *
 * \param instance identifier of the service.
 *
 * \return true on success, meaning AServiceManager_waitForService should always
 *    be able to return the service.
 */
bool AServiceManager_isDeclared(const char* instance) __INTRODUCED_IN(31);

__END_DECLS
