/*
 * Copyright (C) 2019 The Android Open Source Project
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

package android.os;

/**
 * @hide
 */
oneway interface IClientCallback {
    /**
     * This is called when there is a transition between having >= 1 clients and having 0 clients
     * (or vice versa).
     *
     * Upon receiving hasClients false, if the process decides to exit, it is recommended to try to
     * unregister using IServiceManager's tryUnregister before quitting in case another client
     * associates.
     *
     * @param registered binder 'server' registered with IServiceManager's registerClientCallback
     * @param hasClients whether there are currently clients
     *     true - when there are >= 1 clients. This must be called as soon as IServiceManager::get
     *         is called (no race).
     *     false - when there are 0 clients. This may be delayed if it is thought that another
     *         may be used again soon.
     */
    void onClients(IBinder registered, boolean hasClients);
}
