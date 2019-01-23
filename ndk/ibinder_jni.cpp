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

#include <android/binder_ibinder_jni.h>
#include "ibinder_internal.h"

#include <android-base/logging.h>
#include <binder/IBinder.h>

#include <mutex>

#include <dlfcn.h>

using ::android::IBinder;
using ::android::sp;

struct LazyAndroidRuntime {
    typedef sp<IBinder> (*FromJava)(JNIEnv* env, jobject obj);
    typedef jobject (*ToJava)(JNIEnv* env, const sp<IBinder>& val);

    static FromJava ibinderForJavaObject;
    static ToJava javaObjectForIBinder;

    static void load() {
        std::call_once(mLoadFlag, []() {
            void* handle = dlopen("libandroid_runtime.so", RTLD_LAZY);
            if (handle == nullptr) {
                LOG(WARNING) << "Could not open libandroid_runtime.";
                return;
            }

            ibinderForJavaObject = reinterpret_cast<FromJava>(
                    dlsym(handle, "_ZN7android20ibinderForJavaObjectEP7_JNIEnvP8_jobject"));
            if (ibinderForJavaObject == nullptr) {
                LOG(WARNING) << "Could not find ibinderForJavaObject.";
                // no return
            }

            javaObjectForIBinder = reinterpret_cast<ToJava>(dlsym(
                    handle, "_ZN7android20javaObjectForIBinderEP7_JNIEnvRKNS_2spINS_7IBinderEEE"));
            if (javaObjectForIBinder == nullptr) {
                LOG(WARNING) << "Could not find javaObjectForIBinder.";
                // no return
            }
        });
    }

   private:
    static std::once_flag mLoadFlag;

    LazyAndroidRuntime(){};
};

LazyAndroidRuntime::FromJava LazyAndroidRuntime::ibinderForJavaObject = nullptr;
LazyAndroidRuntime::ToJava LazyAndroidRuntime::javaObjectForIBinder = nullptr;
std::once_flag LazyAndroidRuntime::mLoadFlag;

AIBinder* AIBinder_fromJavaBinder(JNIEnv* env, jobject binder) {
    if (binder == nullptr) {
        return nullptr;
    }

    LazyAndroidRuntime::load();
    if (LazyAndroidRuntime::ibinderForJavaObject == nullptr) {
        return nullptr;
    }

    sp<IBinder> ibinder = (LazyAndroidRuntime::ibinderForJavaObject)(env, binder);

    sp<AIBinder> cbinder = ABpBinder::lookupOrCreateFromBinder(ibinder);
    AIBinder_incStrong(cbinder.get());

    return cbinder.get();
}

jobject AIBinder_toJavaBinder(JNIEnv* env, AIBinder* binder) {
    if (binder == nullptr) {
        return nullptr;
    }

    LazyAndroidRuntime::load();
    if (LazyAndroidRuntime::javaObjectForIBinder == nullptr) {
        return nullptr;
    }

    return (LazyAndroidRuntime::javaObjectForIBinder)(env, binder->getBinder());
}
