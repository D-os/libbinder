/*
 * Copyright 2020 The Android Open Source Project
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

#include <binder/Parcel.h>
#include <binder/Parcelable.h>
#include <binder/PersistableBundle.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <utils/String16.h>
#include <utils/StrongPointer.h>
#include <map>
#include <set>
#include <vector>

namespace android {

/* This is a vector of lambda functions the fuzzer will pull from.
 *  This is done so new functions can be added to the fuzzer easily
 *  without requiring modifications to the main fuzzer file. This also
 *  allows multiple fuzzers to include this file, if functionality is needed.
 */
static const std::vector<std::function<
        void(FuzzedDataProvider*, std::shared_ptr<os::PersistableBundle> const&, String16*)>>
        gPersistableBundleOperations =
                {[](FuzzedDataProvider*, std::shared_ptr<os::PersistableBundle> const& p_bundle,
                    String16*) -> void { p_bundle->empty(); },
                 [](FuzzedDataProvider*, std::shared_ptr<os::PersistableBundle> const& p_bundle,
                    String16*) -> void {
                     Parcel parcel;
                     p_bundle->writeToParcel(&parcel);
                 },
                 [](FuzzedDataProvider* fdp, std::shared_ptr<os::PersistableBundle> const& p_bundle,
                    String16*) -> void {
                     Parcel parcel;
                     std::vector<uint8_t> buf = fdp->ConsumeBytes<uint8_t>(
                             fdp->ConsumeIntegralInRange<size_t>(0, fdp->remaining_bytes() - 1));
                     parcel.write(buf.data(), buf.size());
                     p_bundle->readFromParcel(&parcel);
                 },
                 [](FuzzedDataProvider*, std::shared_ptr<os::PersistableBundle> const& p_bundle,
                    String16*) -> void { p_bundle->size(); },
                 [](FuzzedDataProvider*, std::shared_ptr<os::PersistableBundle> const& p_bundle,
                    String16* key) -> void { p_bundle->erase(*key); },
                 [](FuzzedDataProvider* fdp, std::shared_ptr<os::PersistableBundle> const& p_bundle,
                    String16* key) -> void {
                     bool value = fdp->ConsumeBool();
                     p_bundle->putBoolean(*key, value);
                 },
                 [](FuzzedDataProvider* fdp, std::shared_ptr<os::PersistableBundle> const& p_bundle,
                    String16* key) -> void {
                     int32_t value = fdp->ConsumeIntegral<int32_t>();
                     p_bundle->putInt(*key, value);
                 },
                 [](FuzzedDataProvider*, std::shared_ptr<os::PersistableBundle> const& p_bundle,
                    String16* key) -> void {
                     os::PersistableBundle value = os::PersistableBundle();
                     p_bundle->putPersistableBundle(*key, value);
                 },
                 [](FuzzedDataProvider*, std::shared_ptr<os::PersistableBundle> const& p_bundle,
                    String16* key) -> void {
                     std::vector<String16> value;
                     p_bundle->putStringVector(*key, value);
                 },
                 [](FuzzedDataProvider*, std::shared_ptr<os::PersistableBundle> const& p_bundle,
                    String16* key) -> void {
                     std::vector<double> value;
                     p_bundle->putDoubleVector(*key, value);
                 },
                 [](FuzzedDataProvider*, std::shared_ptr<os::PersistableBundle> const& p_bundle,
                    String16* key) -> void {
                     std::vector<int64_t> value;
                     p_bundle->putLongVector(*key, value);
                 },
                 [](FuzzedDataProvider*, std::shared_ptr<os::PersistableBundle> const& p_bundle,
                    String16* key) -> void {
                     std::vector<int32_t> value;
                     p_bundle->putIntVector(*key, value);
                 },
                 [](FuzzedDataProvider*, std::shared_ptr<os::PersistableBundle> const& p_bundle,
                    String16* key) -> void {
                     std::vector<bool> value;
                     p_bundle->putBooleanVector(*key, value);
                 },
                 [](FuzzedDataProvider* fdp, std::shared_ptr<os::PersistableBundle> const& p_bundle,
                    String16* key) -> void {
                     String16 value(fdp->ConsumeRandomLengthString(fdp->remaining_bytes()).c_str());
                     p_bundle->putString(*key, value);
                 },
                 [](FuzzedDataProvider* fdp, std::shared_ptr<os::PersistableBundle> const& p_bundle,
                    String16* key) -> void {
                     int64_t value = fdp->ConsumeIntegral<int64_t>();
                     p_bundle->putLong(*key, value);
                 },
                 [](FuzzedDataProvider* fdp, std::shared_ptr<os::PersistableBundle> const& p_bundle,
                    String16* key) -> void {
                     double value = fdp->ConsumeFloatingPoint<double>();
                     p_bundle->putDouble(*key, value);
                 },
                 [](FuzzedDataProvider*, std::shared_ptr<os::PersistableBundle> const& p_bundle,
                    String16* key) -> void {
                     bool out;
                     p_bundle->getBoolean(*key, &out);
                 },
                 [](FuzzedDataProvider*, std::shared_ptr<os::PersistableBundle> const& p_bundle,
                    String16* key) -> void {
                     os::PersistableBundle out;
                     p_bundle->getPersistableBundle(*key, &out);
                 },
                 [](FuzzedDataProvider*, std::shared_ptr<os::PersistableBundle> const& p_bundle,
                    String16* key) -> void {
                     std::vector<String16> out;
                     p_bundle->getStringVector(*key, &out);
                 },
                 [](FuzzedDataProvider*, std::shared_ptr<os::PersistableBundle> const& p_bundle,
                    String16* key) -> void {
                     std::vector<double> out;
                     p_bundle->getDoubleVector(*key, &out);
                 },
                 [](FuzzedDataProvider*, std::shared_ptr<os::PersistableBundle> const& p_bundle,
                    String16* key) -> void {
                     std::vector<int64_t> out;
                     p_bundle->getLongVector(*key, &out);
                 },
                 [](FuzzedDataProvider*, std::shared_ptr<os::PersistableBundle> const& p_bundle,
                    String16* key) -> void {
                     std::vector<int32_t> out;
                     p_bundle->getIntVector(*key, &out);
                 },
                 [](FuzzedDataProvider*, std::shared_ptr<os::PersistableBundle> const& p_bundle,
                    String16* key) -> void {
                     std::vector<bool> out;
                     p_bundle->getBooleanVector(*key, &out);
                 },
                 [](FuzzedDataProvider*, std::shared_ptr<os::PersistableBundle> const& p_bundle,
                    String16* key) -> void {
                     String16 out;
                     p_bundle->getString(*key, &out);
                 },
                 [](FuzzedDataProvider*, std::shared_ptr<os::PersistableBundle> const& p_bundle,
                    String16* key) -> void {
                     double out;
                     p_bundle->getDouble(*key, &out);
                 },
                 [](FuzzedDataProvider*, std::shared_ptr<os::PersistableBundle> const& p_bundle,
                    String16* key) -> void {
                     int64_t out;
                     p_bundle->getLong(*key, &out);
                 },
                 [](FuzzedDataProvider*, std::shared_ptr<os::PersistableBundle> const& p_bundle,
                    String16* key) -> void {
                     int32_t out;
                     p_bundle->getInt(*key, &out);
                 },
                 [](FuzzedDataProvider*, std::shared_ptr<os::PersistableBundle> const& p_bundle,
                    String16*) -> void {
                     p_bundle->getBooleanKeys();
                     p_bundle->getIntKeys();
                     p_bundle->getLongKeys();
                     p_bundle->getDoubleKeys();
                     p_bundle->getStringKeys();
                     p_bundle->getBooleanVectorKeys();
                     p_bundle->getIntVectorKeys();
                     p_bundle->getLongVectorKeys();
                     p_bundle->getDoubleVectorKeys();
                     p_bundle->getStringVectorKeys();
                     p_bundle->getPersistableBundleKeys();
                 }};

} // namespace android
