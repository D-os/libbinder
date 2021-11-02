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

//! This crate lets you use the Tokio `spawn_blocking` pool with AIDL in async
//! Rust code.
//!
//! This crate works by defining a type [`Tokio`], which you can use as the
//! generic parameter in the async version of the trait generated by the AIDL
//! compiler.
//! ```text
//! use binder_tokio::Tokio;
//!
//! binder::get_interface::<dyn SomeAsyncInterface<Tokio>>("...").
//! ```
//!
//! [`Tokio`]: crate::Tokio

use binder::public_api::{BinderAsyncPool, BoxFuture, Strong};
use binder::{FromIBinder, StatusCode};
use std::future::Future;

/// Retrieve an existing service for a particular interface, sleeping for a few
/// seconds if it doesn't yet exist.
pub async fn get_interface<T: FromIBinder + ?Sized + 'static>(name: &str) -> Result<Strong<T>, StatusCode> {
    let name = name.to_string();
    let res = tokio::task::spawn_blocking(move || {
        binder::public_api::get_interface::<T>(&name)
    }).await;

    // The `is_panic` branch is not actually reachable in Android as we compile
    // with `panic = abort`.
    match res {
        Ok(Ok(service)) => Ok(service),
        Ok(Err(err)) => Err(err),
        Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
        Err(e) if e.is_cancelled() => Err(StatusCode::FAILED_TRANSACTION),
        Err(_) => Err(StatusCode::UNKNOWN_ERROR),
    }
}

/// Retrieve an existing service for a particular interface, or start it if it
/// is configured as a dynamic service and isn't yet started.
pub async fn wait_for_interface<T: FromIBinder + ?Sized + 'static>(name: &str) -> Result<Strong<T>, StatusCode> {
    let name = name.to_string();
    let res = tokio::task::spawn_blocking(move || {
        binder::public_api::wait_for_interface::<T>(&name)
    }).await;

    // The `is_panic` branch is not actually reachable in Android as we compile
    // with `panic = abort`.
    match res {
        Ok(Ok(service)) => Ok(service),
        Ok(Err(err)) => Err(err),
        Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
        Err(e) if e.is_cancelled() => Err(StatusCode::FAILED_TRANSACTION),
        Err(_) => Err(StatusCode::UNKNOWN_ERROR),
    }
}

/// Use the Tokio `spawn_blocking` pool with AIDL.
pub enum Tokio {}

impl BinderAsyncPool for Tokio {
    fn spawn<'a, F1, F2, Fut, A, B, E>(spawn_me: F1, after_spawn: F2) -> BoxFuture<'a, Result<B, E>>
    where
        F1: FnOnce() -> A,
        F2: FnOnce(A) -> Fut,
        Fut: Future<Output = Result<B, E>>,
        F1: Send + 'static,
        F2: Send + 'a,
        Fut: Send + 'a,
        A: Send + 'static,
        B: Send + 'a,
        E: From<crate::StatusCode>,
    {
        let handle = tokio::task::spawn_blocking(spawn_me);
        Box::pin(async move {
            // The `is_panic` branch is not actually reachable in Android as we compile
            // with `panic = abort`.
            match handle.await {
                Ok(res) => after_spawn(res).await,
                Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
                Err(e) if e.is_cancelled() => Err(StatusCode::FAILED_TRANSACTION.into()),
                Err(_) => Err(StatusCode::UNKNOWN_ERROR.into()),
            }
        })
    }
}


