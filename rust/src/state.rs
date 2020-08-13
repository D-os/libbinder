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

use crate::sys;

use libc::{pid_t, uid_t};

/// Static utility functions to manage Binder process state.
pub struct ProcessState;

impl ProcessState {
    /// Start the Binder IPC thread pool
    pub fn start_thread_pool() {
        unsafe {
            // Safety: Safe FFI
            sys::ABinderProcess_startThreadPool();
        }
    }

    /// Set the maximum number of threads that can be started in the threadpool.
    ///
    /// By default, after startThreadPool is called, this is 15. If it is called
    /// additional times, it will only prevent the kernel from starting new
    /// threads and will not delete already existing threads.
    pub fn set_thread_pool_max_thread_count(num_threads: u32) {
        unsafe {
            // Safety: Safe FFI
            sys::ABinderProcess_setThreadPoolMaxThreadCount(num_threads);
        }
    }

    /// Block on the Binder IPC thread pool
    pub fn join_thread_pool() {
        unsafe {
            // Safety: Safe FFI
            sys::ABinderProcess_joinThreadPool();
        }
    }
}

/// Static utility functions to manage Binder thread state.
pub struct ThreadState;

impl ThreadState {
    /// This returns the calling UID assuming that this thread is called from a
    /// thread that is processing a binder transaction (for instance, in the
    /// implementation of
    /// [`Remotable::on_transact`](crate::Remotable::on_transact)).
    ///
    /// This can be used with higher-level system services to determine the
    /// caller's identity and check permissions.
    ///
    /// Available since API level 29.
    ///
    /// \return calling uid or the current process's UID if this thread isn't
    /// processing a transaction.
    pub fn get_calling_uid() -> uid_t {
        unsafe {
            // Safety: Safe FFI
            sys::AIBinder_getCallingUid()
        }
    }

    /// This returns the calling PID assuming that this thread is called from a
    /// thread that is processing a binder transaction (for instance, in the
    /// implementation of
    /// [`Remotable::on_transact`](crate::Remotable::on_transact)).
    ///
    /// This can be used with higher-level system services to determine the
    /// caller's identity and check permissions. However, when doing this, one
    /// should be aware of possible TOCTOU problems when the calling process
    /// dies and is replaced with another process with elevated permissions and
    /// the same PID.
    ///
    /// Available since API level 29.
    ///
    /// \return calling pid or the current process's PID if this thread isn't
    /// processing a transaction.
    ///
    /// If the transaction being processed is a oneway transaction, then this
    /// method will return 0.
    pub fn get_calling_pid() -> pid_t {
        unsafe {
            // Safety: Safe FFI
            sys::AIBinder_getCallingPid()
        }
    }
}
