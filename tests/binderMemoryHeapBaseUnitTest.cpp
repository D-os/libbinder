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

#include <binder/MemoryHeapBase.h>
#include <cutils/ashmem.h>
#include <fcntl.h>

#include <gtest/gtest.h>
using namespace android;
#ifdef __BIONIC__
TEST(MemoryHeapBase, ForceMemfdRespected) {
    auto mHeap = sp<MemoryHeapBase>::make(10, MemoryHeapBase::FORCE_MEMFD, "Test mapping");
    int fd = mHeap->getHeapID();
    EXPECT_NE(fd, -1);
    EXPECT_FALSE(ashmem_valid(fd));
    EXPECT_NE(fcntl(fd, F_GET_SEALS), -1);
}

TEST(MemoryHeapBase, MemfdSealed) {
    auto mHeap = sp<MemoryHeapBase>::make(8192,
                                          MemoryHeapBase::FORCE_MEMFD,
                                          "Test mapping");
    int fd = mHeap->getHeapID();
    EXPECT_NE(fd, -1);
    EXPECT_EQ(fcntl(fd, F_GET_SEALS), F_SEAL_SEAL);
}

TEST(MemoryHeapBase, MemfdUnsealed) {
    auto mHeap = sp<MemoryHeapBase>::make(8192,
                                          MemoryHeapBase::FORCE_MEMFD |
                                          MemoryHeapBase::MEMFD_ALLOW_SEALING,
                                          "Test mapping");
    int fd = mHeap->getHeapID();
    EXPECT_NE(fd, -1);
    EXPECT_EQ(fcntl(fd, F_GET_SEALS), 0);
}

TEST(MemoryHeapBase, MemfdSealedProtected) {
    auto mHeap = sp<MemoryHeapBase>::make(8192,
                                          MemoryHeapBase::FORCE_MEMFD |
                                          MemoryHeapBase::READ_ONLY,
                                          "Test mapping");
    int fd = mHeap->getHeapID();
    EXPECT_NE(fd, -1);
    EXPECT_EQ(fcntl(fd, F_GET_SEALS), F_SEAL_SEAL | F_SEAL_FUTURE_WRITE);
}

TEST(MemoryHeapBase, MemfdUnsealedProtected) {
    auto mHeap = sp<MemoryHeapBase>::make(8192,
                                          MemoryHeapBase::FORCE_MEMFD |
                                          MemoryHeapBase::READ_ONLY |
                                          MemoryHeapBase::MEMFD_ALLOW_SEALING,
                                          "Test mapping");
    int fd = mHeap->getHeapID();
    EXPECT_NE(fd, -1);
    EXPECT_EQ(fcntl(fd, F_GET_SEALS), F_SEAL_FUTURE_WRITE);
}

#else
TEST(MemoryHeapBase, HostMemfdExpected) {
    auto mHeap = sp<MemoryHeapBase>::make(8192,
                                          MemoryHeapBase::READ_ONLY,
                                          "Test mapping");
    int fd = mHeap->getHeapID();
    void* ptr = mHeap->getBase();
    EXPECT_NE(ptr, MAP_FAILED);
    EXPECT_TRUE(ashmem_valid(fd));
    EXPECT_EQ(mHeap->getFlags(), MemoryHeapBase::READ_ONLY);
}

TEST(MemoryHeapBase,HostMemfdException) {
    auto mHeap = sp<MemoryHeapBase>::make(8192,
                                          MemoryHeapBase::FORCE_MEMFD |
                                          MemoryHeapBase::READ_ONLY |
                                          MemoryHeapBase::MEMFD_ALLOW_SEALING,
                                          "Test mapping");
    int fd = mHeap->getHeapID();
    void* ptr = mHeap->getBase();
    EXPECT_EQ(mHeap->getFlags(), MemoryHeapBase::READ_ONLY);
    EXPECT_TRUE(ashmem_valid(fd));
    EXPECT_NE(ptr, MAP_FAILED);
}

#endif
