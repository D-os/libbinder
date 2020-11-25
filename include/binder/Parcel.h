/*
 * Copyright (C) 2005 The Android Open Source Project
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

#include <map> // for legacy reasons
#include <string>
#include <type_traits>
#include <vector>

#include <android-base/unique_fd.h>
#include <cutils/native_handle.h>
#include <utils/Errors.h>
#include <utils/RefBase.h>
#include <utils/String16.h>
#include <utils/Vector.h>
#include <utils/Flattenable.h>

#include <binder/IInterface.h>
#include <binder/Parcelable.h>

#ifdef BINDER_IPC_32BIT
//NOLINTNEXTLINE(google-runtime-int) b/173188702
typedef unsigned int binder_size_t;
#else
//NOLINTNEXTLINE(google-runtime-int) b/173188702
typedef unsigned long long binder_size_t;
#endif

struct flat_binder_object;

// ---------------------------------------------------------------------------
namespace android {

template <typename T> class Flattenable;
template <typename T> class LightFlattenable;
class IBinder;
class IPCThreadState;
class ProcessState;
class String8;
class TextOutput;

class Parcel {
    friend class IPCThreadState;
public:
    class ReadableBlob;
    class WritableBlob;

                        Parcel();
                        ~Parcel();
    
    const uint8_t*      data() const;
    size_t              dataSize() const;
    size_t              dataAvail() const;
    size_t              dataPosition() const;
    size_t              dataCapacity() const;

    status_t            setDataSize(size_t size);
    void                setDataPosition(size_t pos) const;
    status_t            setDataCapacity(size_t size);

    status_t            setData(const uint8_t* buffer, size_t len);

    status_t            appendFrom(const Parcel *parcel,
                                   size_t start, size_t len);

    int                 compareData(const Parcel& other);

    bool                allowFds() const;
    bool                pushAllowFds(bool allowFds);
    void                restoreAllowFds(bool lastValue);

    bool                hasFileDescriptors() const;

    // Zeros data when reallocating. Other mitigations may be added
    // in the future.
    //
    // WARNING: some read methods may make additional copies of data.
    // In order to verify this, heap dumps should be used.
    void                markSensitive() const;

    // Writes the RPC header.
    status_t            writeInterfaceToken(const String16& interface);
    status_t            writeInterfaceToken(const char16_t* str, size_t len);

    // Parses the RPC header, returning true if the interface name
    // in the header matches the expected interface from the caller.
    //
    // Additionally, enforceInterface does part of the work of
    // propagating the StrictMode policy mask, populating the current
    // IPCThreadState, which as an optimization may optionally be
    // passed in.
    bool                enforceInterface(const String16& interface,
                                         IPCThreadState* threadState = nullptr) const;
    bool                enforceInterface(const char16_t* interface,
                                         size_t len,
                                         IPCThreadState* threadState = nullptr) const;
    bool                checkInterface(IBinder*) const;

    void                freeData();

    size_t              objectsCount() const;
    
    status_t            errorCheck() const;
    void                setError(status_t err);
    
    status_t            write(const void* data, size_t len);
    void*               writeInplace(size_t len);
    status_t            writeUnpadded(const void* data, size_t len);
    status_t            writeInt32(int32_t val);
    status_t            writeUint32(uint32_t val);
    status_t            writeInt64(int64_t val);
    status_t            writeUint64(uint64_t val);
    status_t            writeFloat(float val);
    status_t            writeDouble(double val);
    status_t            writeCString(const char* str);
    status_t            writeString8(const String8& str);
    status_t            writeString8(const char* str, size_t len);
    status_t            writeString16(const String16& str);
    status_t            writeString16(const std::optional<String16>& str);
    status_t            writeString16(const std::unique_ptr<String16>& str) __attribute__((deprecated("use std::optional version instead")));
    status_t            writeString16(const char16_t* str, size_t len);
    status_t            writeStrongBinder(const sp<IBinder>& val);
    status_t            writeInt32Array(size_t len, const int32_t *val);
    status_t            writeByteArray(size_t len, const uint8_t *val);
    status_t            writeBool(bool val);
    status_t            writeChar(char16_t val);
    status_t            writeByte(int8_t val);

    // Take a UTF8 encoded string, convert to UTF16, write it to the parcel.
    status_t            writeUtf8AsUtf16(const std::string& str);
    status_t            writeUtf8AsUtf16(const std::optional<std::string>& str);
    status_t            writeUtf8AsUtf16(const std::unique_ptr<std::string>& str) __attribute__((deprecated("use std::optional version instead")));

    status_t            writeByteVector(const std::optional<std::vector<int8_t>>& val);
    status_t            writeByteVector(const std::unique_ptr<std::vector<int8_t>>& val) __attribute__((deprecated("use std::optional version instead")));
    status_t            writeByteVector(const std::vector<int8_t>& val);
    status_t            writeByteVector(const std::optional<std::vector<uint8_t>>& val);
    status_t            writeByteVector(const std::unique_ptr<std::vector<uint8_t>>& val) __attribute__((deprecated("use std::optional version instead")));
    status_t            writeByteVector(const std::vector<uint8_t>& val);
    status_t            writeInt32Vector(const std::optional<std::vector<int32_t>>& val);
    status_t            writeInt32Vector(const std::unique_ptr<std::vector<int32_t>>& val) __attribute__((deprecated("use std::optional version instead")));
    status_t            writeInt32Vector(const std::vector<int32_t>& val);
    status_t            writeInt64Vector(const std::optional<std::vector<int64_t>>& val);
    status_t            writeInt64Vector(const std::unique_ptr<std::vector<int64_t>>& val) __attribute__((deprecated("use std::optional version instead")));
    status_t            writeInt64Vector(const std::vector<int64_t>& val);
    status_t            writeUint64Vector(const std::optional<std::vector<uint64_t>>& val);
    status_t            writeUint64Vector(const std::unique_ptr<std::vector<uint64_t>>& val) __attribute__((deprecated("use std::optional version instead")));
    status_t            writeUint64Vector(const std::vector<uint64_t>& val);
    status_t            writeFloatVector(const std::optional<std::vector<float>>& val);
    status_t            writeFloatVector(const std::unique_ptr<std::vector<float>>& val) __attribute__((deprecated("use std::optional version instead")));
    status_t            writeFloatVector(const std::vector<float>& val);
    status_t            writeDoubleVector(const std::optional<std::vector<double>>& val);
    status_t            writeDoubleVector(const std::unique_ptr<std::vector<double>>& val) __attribute__((deprecated("use std::optional version instead")));
    status_t            writeDoubleVector(const std::vector<double>& val);
    status_t            writeBoolVector(const std::optional<std::vector<bool>>& val);
    status_t            writeBoolVector(const std::unique_ptr<std::vector<bool>>& val) __attribute__((deprecated("use std::optional version instead")));
    status_t            writeBoolVector(const std::vector<bool>& val);
    status_t            writeCharVector(const std::optional<std::vector<char16_t>>& val);
    status_t            writeCharVector(const std::unique_ptr<std::vector<char16_t>>& val) __attribute__((deprecated("use std::optional version instead")));
    status_t            writeCharVector(const std::vector<char16_t>& val);
    status_t            writeString16Vector(
                            const std::optional<std::vector<std::optional<String16>>>& val);
    status_t            writeString16Vector(
                            const std::unique_ptr<std::vector<std::unique_ptr<String16>>>& val) __attribute__((deprecated("use std::optional version instead")));
    status_t            writeString16Vector(const std::vector<String16>& val);
    status_t            writeUtf8VectorAsUtf16Vector(
                            const std::optional<std::vector<std::optional<std::string>>>& val);
    status_t            writeUtf8VectorAsUtf16Vector(
                            const std::unique_ptr<std::vector<std::unique_ptr<std::string>>>& val) __attribute__((deprecated("use std::optional version instead")));
    status_t            writeUtf8VectorAsUtf16Vector(const std::vector<std::string>& val);

    status_t            writeStrongBinderVector(const std::optional<std::vector<sp<IBinder>>>& val);
    status_t            writeStrongBinderVector(const std::unique_ptr<std::vector<sp<IBinder>>>& val) __attribute__((deprecated("use std::optional version instead")));
    status_t            writeStrongBinderVector(const std::vector<sp<IBinder>>& val);

    // Write an Enum vector with underlying type int8_t.
    // Does not use padding; each byte is contiguous.
    template<typename T, std::enable_if_t<std::is_enum_v<T> && std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool> = 0>
    status_t            writeEnumVector(const std::vector<T>& val);
    template<typename T, std::enable_if_t<std::is_enum_v<T> && std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool> = 0>
    status_t            writeEnumVector(const std::optional<std::vector<T>>& val);
    template<typename T, std::enable_if_t<std::is_enum_v<T> && std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool> = 0>
    status_t            writeEnumVector(const std::unique_ptr<std::vector<T>>& val) __attribute__((deprecated("use std::optional version instead")));
    // Write an Enum vector with underlying type != int8_t.
    template<typename T, std::enable_if_t<std::is_enum_v<T> && !std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool> = 0>
    status_t            writeEnumVector(const std::vector<T>& val);
    template<typename T, std::enable_if_t<std::is_enum_v<T> && !std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool> = 0>
    status_t            writeEnumVector(const std::optional<std::vector<T>>& val);
    template<typename T, std::enable_if_t<std::is_enum_v<T> && !std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool> = 0>
    status_t            writeEnumVector(const std::unique_ptr<std::vector<T>>& val) __attribute__((deprecated("use std::optional version instead")));

    template<typename T>
    status_t            writeParcelableVector(const std::optional<std::vector<std::optional<T>>>& val);
    template<typename T>
    status_t            writeParcelableVector(const std::unique_ptr<std::vector<std::unique_ptr<T>>>& val) __attribute__((deprecated("use std::optional version instead")));
    template<typename T>
    status_t            writeParcelableVector(const std::shared_ptr<std::vector<std::unique_ptr<T>>>& val) __attribute__((deprecated("use std::optional version instead")));
    template<typename T>
    status_t            writeParcelableVector(const std::shared_ptr<std::vector<std::optional<T>>>& val);
    template<typename T>
    status_t            writeParcelableVector(const std::vector<T>& val);

    template<typename T>
    status_t            writeNullableParcelable(const std::optional<T>& parcelable);
    template<typename T>
    status_t            writeNullableParcelable(const std::unique_ptr<T>& parcelable) __attribute__((deprecated("use std::optional version instead")));

    status_t            writeParcelable(const Parcelable& parcelable);

    template<typename T>
    status_t            write(const Flattenable<T>& val);

    template<typename T>
    status_t            write(const LightFlattenable<T>& val);

    template<typename T>
    status_t            writeVectorSize(const std::vector<T>& val);
    template<typename T>
    status_t            writeVectorSize(const std::optional<std::vector<T>>& val);
    template<typename T>
    status_t            writeVectorSize(const std::unique_ptr<std::vector<T>>& val) __attribute__((deprecated("use std::optional version instead")));

    // Place a native_handle into the parcel (the native_handle's file-
    // descriptors are dup'ed, so it is safe to delete the native_handle
    // when this function returns).
    // Doesn't take ownership of the native_handle.
    status_t            writeNativeHandle(const native_handle* handle);

    // Place a file descriptor into the parcel.  The given fd must remain
    // valid for the lifetime of the parcel.
    // The Parcel does not take ownership of the given fd unless you ask it to.
    status_t            writeFileDescriptor(int fd, bool takeOwnership = false);

    // Place a file descriptor into the parcel.  A dup of the fd is made, which
    // will be closed once the parcel is destroyed.
    status_t            writeDupFileDescriptor(int fd);

    // Place a Java "parcel file descriptor" into the parcel.  The given fd must remain
    // valid for the lifetime of the parcel.
    // The Parcel does not take ownership of the given fd unless you ask it to.
    status_t            writeParcelFileDescriptor(int fd, bool takeOwnership = false);

    // Place a Java "parcel file descriptor" into the parcel.  A dup of the fd is made, which will
    // be closed once the parcel is destroyed.
    status_t            writeDupParcelFileDescriptor(int fd);

    // Place a file descriptor into the parcel.  This will not affect the
    // semantics of the smart file descriptor. A new descriptor will be
    // created, and will be closed when the parcel is destroyed.
    status_t            writeUniqueFileDescriptor(
                            const base::unique_fd& fd);

    // Place a vector of file desciptors into the parcel. Each descriptor is
    // dup'd as in writeDupFileDescriptor
    status_t            writeUniqueFileDescriptorVector(
                            const std::optional<std::vector<base::unique_fd>>& val);
    status_t            writeUniqueFileDescriptorVector(
                            const std::unique_ptr<std::vector<base::unique_fd>>& val) __attribute__((deprecated("use std::optional version instead")));
    status_t            writeUniqueFileDescriptorVector(
                            const std::vector<base::unique_fd>& val);

    // Writes a blob to the parcel.
    // If the blob is small, then it is stored in-place, otherwise it is
    // transferred by way of an anonymous shared memory region.  Prefer sending
    // immutable blobs if possible since they may be subsequently transferred between
    // processes without further copying whereas mutable blobs always need to be copied.
    // The caller should call release() on the blob after writing its contents.
    status_t            writeBlob(size_t len, bool mutableCopy, WritableBlob* outBlob);

    // Write an existing immutable blob file descriptor to the parcel.
    // This allows the client to send the same blob to multiple processes
    // as long as it keeps a dup of the blob file descriptor handy for later.
    status_t            writeDupImmutableBlobFileDescriptor(int fd);

    status_t            writeObject(const flat_binder_object& val, bool nullMetaData);

    // Like Parcel.java's writeNoException().  Just writes a zero int32.
    // Currently the native implementation doesn't do any of the StrictMode
    // stack gathering and serialization that the Java implementation does.
    status_t            writeNoException();
    
    status_t            read(void* outData, size_t len) const;
    const void*         readInplace(size_t len) const;
    int32_t             readInt32() const;
    status_t            readInt32(int32_t *pArg) const;
    uint32_t            readUint32() const;
    status_t            readUint32(uint32_t *pArg) const;
    int64_t             readInt64() const;
    status_t            readInt64(int64_t *pArg) const;
    uint64_t            readUint64() const;
    status_t            readUint64(uint64_t *pArg) const;
    float               readFloat() const;
    status_t            readFloat(float *pArg) const;
    double              readDouble() const;
    status_t            readDouble(double *pArg) const;
    bool                readBool() const;
    status_t            readBool(bool *pArg) const;
    char16_t            readChar() const;
    status_t            readChar(char16_t *pArg) const;
    int8_t              readByte() const;
    status_t            readByte(int8_t *pArg) const;

    // Read a UTF16 encoded string, convert to UTF8
    status_t            readUtf8FromUtf16(std::string* str) const;
    status_t            readUtf8FromUtf16(std::optional<std::string>* str) const;
    status_t            readUtf8FromUtf16(std::unique_ptr<std::string>* str) const __attribute__((deprecated("use std::optional version instead")));

    const char*         readCString() const;
    String8             readString8() const;
    status_t            readString8(String8* pArg) const;
    const char*         readString8Inplace(size_t* outLen) const;
    String16            readString16() const;
    status_t            readString16(String16* pArg) const;
    status_t            readString16(std::optional<String16>* pArg) const;
    status_t            readString16(std::unique_ptr<String16>* pArg) const __attribute__((deprecated("use std::optional version instead")));
    const char16_t*     readString16Inplace(size_t* outLen) const;
    sp<IBinder>         readStrongBinder() const;
    status_t            readStrongBinder(sp<IBinder>* val) const;
    status_t            readNullableStrongBinder(sp<IBinder>* val) const;

    // Read an Enum vector with underlying type int8_t.
    // Does not use padding; each byte is contiguous.
    template<typename T, std::enable_if_t<std::is_enum_v<T> && std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool> = 0>
    status_t            readEnumVector(std::vector<T>* val) const;
    template<typename T, std::enable_if_t<std::is_enum_v<T> && std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool> = 0>
    status_t            readEnumVector(std::unique_ptr<std::vector<T>>* val) const __attribute__((deprecated("use std::optional version instead")));
    template<typename T, std::enable_if_t<std::is_enum_v<T> && std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool> = 0>
    status_t            readEnumVector(std::optional<std::vector<T>>* val) const;
    // Read an Enum vector with underlying type != int8_t.
    template<typename T, std::enable_if_t<std::is_enum_v<T> && !std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool> = 0>
    status_t            readEnumVector(std::vector<T>* val) const;
    template<typename T, std::enable_if_t<std::is_enum_v<T> && !std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool> = 0>
    status_t            readEnumVector(std::unique_ptr<std::vector<T>>* val) const __attribute__((deprecated("use std::optional version instead")));
    template<typename T, std::enable_if_t<std::is_enum_v<T> && !std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool> = 0>
    status_t            readEnumVector(std::optional<std::vector<T>>* val) const;

    template<typename T>
    status_t            readParcelableVector(
                            std::optional<std::vector<std::optional<T>>>* val) const;
    template<typename T>
    status_t            readParcelableVector(
                            std::unique_ptr<std::vector<std::unique_ptr<T>>>* val) const __attribute__((deprecated("use std::optional version instead")));
    template<typename T>
    status_t            readParcelableVector(std::vector<T>* val) const;

    status_t            readParcelable(Parcelable* parcelable) const;

    template<typename T>
    status_t            readParcelable(std::optional<T>* parcelable) const;
    template<typename T>
    status_t            readParcelable(std::unique_ptr<T>* parcelable) const __attribute__((deprecated("use std::optional version instead")));

    template<typename T>
    status_t            readStrongBinder(sp<T>* val) const;

    template<typename T>
    status_t            readNullableStrongBinder(sp<T>* val) const;

    status_t            readStrongBinderVector(std::optional<std::vector<sp<IBinder>>>* val) const;
    status_t            readStrongBinderVector(std::unique_ptr<std::vector<sp<IBinder>>>* val) const __attribute__((deprecated("use std::optional version instead")));
    status_t            readStrongBinderVector(std::vector<sp<IBinder>>* val) const;

    status_t            readByteVector(std::optional<std::vector<int8_t>>* val) const;
    status_t            readByteVector(std::unique_ptr<std::vector<int8_t>>* val) const __attribute__((deprecated("use std::optional version instead")));
    status_t            readByteVector(std::vector<int8_t>* val) const;
    status_t            readByteVector(std::optional<std::vector<uint8_t>>* val) const;
    status_t            readByteVector(std::unique_ptr<std::vector<uint8_t>>* val) const __attribute__((deprecated("use std::optional version instead")));
    status_t            readByteVector(std::vector<uint8_t>* val) const;
    status_t            readInt32Vector(std::optional<std::vector<int32_t>>* val) const;
    status_t            readInt32Vector(std::unique_ptr<std::vector<int32_t>>* val) const __attribute__((deprecated("use std::optional version instead")));
    status_t            readInt32Vector(std::vector<int32_t>* val) const;
    status_t            readInt64Vector(std::optional<std::vector<int64_t>>* val) const;
    status_t            readInt64Vector(std::unique_ptr<std::vector<int64_t>>* val) const __attribute__((deprecated("use std::optional version instead")));
    status_t            readInt64Vector(std::vector<int64_t>* val) const;
    status_t            readUint64Vector(std::optional<std::vector<uint64_t>>* val) const;
    status_t            readUint64Vector(std::unique_ptr<std::vector<uint64_t>>* val) const __attribute__((deprecated("use std::optional version instead")));
    status_t            readUint64Vector(std::vector<uint64_t>* val) const;
    status_t            readFloatVector(std::optional<std::vector<float>>* val) const;
    status_t            readFloatVector(std::unique_ptr<std::vector<float>>* val) const __attribute__((deprecated("use std::optional version instead")));
    status_t            readFloatVector(std::vector<float>* val) const;
    status_t            readDoubleVector(std::optional<std::vector<double>>* val) const;
    status_t            readDoubleVector(std::unique_ptr<std::vector<double>>* val) const __attribute__((deprecated("use std::optional version instead")));
    status_t            readDoubleVector(std::vector<double>* val) const;
    status_t            readBoolVector(std::optional<std::vector<bool>>* val) const;
    status_t            readBoolVector(std::unique_ptr<std::vector<bool>>* val) const __attribute__((deprecated("use std::optional version instead")));
    status_t            readBoolVector(std::vector<bool>* val) const;
    status_t            readCharVector(std::optional<std::vector<char16_t>>* val) const;
    status_t            readCharVector(std::unique_ptr<std::vector<char16_t>>* val) const __attribute__((deprecated("use std::optional version instead")));
    status_t            readCharVector(std::vector<char16_t>* val) const;
    status_t            readString16Vector(
                            std::optional<std::vector<std::optional<String16>>>* val) const;
    status_t            readString16Vector(
                            std::unique_ptr<std::vector<std::unique_ptr<String16>>>* val) const __attribute__((deprecated("use std::optional version instead")));
    status_t            readString16Vector(std::vector<String16>* val) const;
    status_t            readUtf8VectorFromUtf16Vector(
                            std::optional<std::vector<std::optional<std::string>>>* val) const;
    status_t            readUtf8VectorFromUtf16Vector(
                            std::unique_ptr<std::vector<std::unique_ptr<std::string>>>* val) const __attribute__((deprecated("use std::optional version instead")));
    status_t            readUtf8VectorFromUtf16Vector(std::vector<std::string>* val) const;

    template<typename T>
    status_t            read(Flattenable<T>& val) const;

    template<typename T>
    status_t            read(LightFlattenable<T>& val) const;

    template<typename T>
    status_t            resizeOutVector(std::vector<T>* val) const;
    template<typename T>
    status_t            resizeOutVector(std::optional<std::vector<T>>* val) const;
    template<typename T>
    status_t            resizeOutVector(std::unique_ptr<std::vector<T>>* val) const __attribute__((deprecated("use std::optional version instead")));
    template<typename T>
    status_t            reserveOutVector(std::vector<T>* val, size_t* size) const;
    template<typename T>
    status_t            reserveOutVector(std::optional<std::vector<T>>* val,
                                         size_t* size) const;
    template<typename T>
    status_t            reserveOutVector(std::unique_ptr<std::vector<T>>* val,
                                         size_t* size) const __attribute__((deprecated("use std::optional version instead")));

    // Like Parcel.java's readExceptionCode().  Reads the first int32
    // off of a Parcel's header, returning 0 or the negative error
    // code on exceptions, but also deals with skipping over rich
    // response headers.  Callers should use this to read & parse the
    // response headers rather than doing it by hand.
    int32_t             readExceptionCode() const;

    // Retrieve native_handle from the parcel. This returns a copy of the
    // parcel's native_handle (the caller takes ownership). The caller
    // must free the native_handle with native_handle_close() and 
    // native_handle_delete().
    native_handle*     readNativeHandle() const;

    
    // Retrieve a file descriptor from the parcel.  This returns the raw fd
    // in the parcel, which you do not own -- use dup() to get your own copy.
    int                 readFileDescriptor() const;

    // Retrieve a Java "parcel file descriptor" from the parcel.  This returns the raw fd
    // in the parcel, which you do not own -- use dup() to get your own copy.
    int                 readParcelFileDescriptor() const;

    // Retrieve a smart file descriptor from the parcel.
    status_t            readUniqueFileDescriptor(
                            base::unique_fd* val) const;

    // Retrieve a Java "parcel file descriptor" from the parcel.
    status_t            readUniqueParcelFileDescriptor(base::unique_fd* val) const;


    // Retrieve a vector of smart file descriptors from the parcel.
    status_t            readUniqueFileDescriptorVector(
                            std::optional<std::vector<base::unique_fd>>* val) const;
    status_t            readUniqueFileDescriptorVector(
                            std::unique_ptr<std::vector<base::unique_fd>>* val) const __attribute__((deprecated("use std::optional version instead")));
    status_t            readUniqueFileDescriptorVector(
                            std::vector<base::unique_fd>* val) const;

    // Reads a blob from the parcel.
    // The caller should call release() on the blob after reading its contents.
    status_t            readBlob(size_t len, ReadableBlob* outBlob) const;

    const flat_binder_object* readObject(bool nullMetaData) const;

    // Explicitly close all file descriptors in the parcel.
    void                closeFileDescriptors();

    // Debugging: get metrics on current allocations.
    static size_t       getGlobalAllocSize();
    static size_t       getGlobalAllocCount();

    bool                replaceCallingWorkSourceUid(uid_t uid);
    // Returns the work source provided by the caller. This can only be trusted for trusted calling
    // uid.
    uid_t               readCallingWorkSourceUid() const;

    void                print(TextOutput& to, uint32_t flags = 0) const;

private:
    typedef void        (*release_func)(Parcel* parcel,
                                        const uint8_t* data, size_t dataSize,
                                        const binder_size_t* objects, size_t objectsSize);

    uintptr_t           ipcData() const;
    size_t              ipcDataSize() const;
    uintptr_t           ipcObjects() const;
    size_t              ipcObjectsCount() const;
    void                ipcSetDataReference(const uint8_t* data, size_t dataSize,
                                            const binder_size_t* objects, size_t objectsCount,
                                            release_func relFunc);

                        Parcel(const Parcel& o);
    Parcel&             operator=(const Parcel& o);
    
    status_t            finishWrite(size_t len);
    void                releaseObjects();
    void                acquireObjects();
    status_t            growData(size_t len);
    status_t            restartWrite(size_t desired);
    status_t            continueWrite(size_t desired);
    status_t            writePointer(uintptr_t val);
    status_t            readPointer(uintptr_t *pArg) const;
    uintptr_t           readPointer() const;
    void                freeDataNoInit();
    void                initState();
    void                scanForFds() const;
    status_t            validateReadData(size_t len) const;
    void                updateWorkSourceRequestHeaderPosition() const;

    status_t            finishFlattenBinder(const sp<IBinder>& binder,
                                            const flat_binder_object& flat);
    status_t            finishUnflattenBinder(const sp<IBinder>& binder, sp<IBinder>* out) const;
    status_t            flattenBinder(const sp<IBinder>& binder);
    status_t            unflattenBinder(sp<IBinder>* out) const;

    template<class T>
    status_t            readAligned(T *pArg) const;

    template<class T>   T readAligned() const;

    template<class T>
    status_t            writeAligned(T val);

    status_t            writeRawNullableParcelable(const Parcelable*
                                                   parcelable);

    template<typename T, std::enable_if_t<std::is_same_v<typename std::underlying_type_t<T>,int32_t>, bool> = 0>
    status_t            writeEnum(const T& val);
    template<typename T, std::enable_if_t<std::is_same_v<typename std::underlying_type_t<T>,int64_t>, bool> = 0>
    status_t            writeEnum(const T& val);

    template<typename T, std::enable_if_t<std::is_same_v<typename std::underlying_type_t<T>,int32_t>, bool> = 0>
    status_t            readEnum(T* pArg) const;
    template<typename T, std::enable_if_t<std::is_same_v<typename std::underlying_type_t<T>,int64_t>, bool> = 0>
    status_t            readEnum(T* pArg) const;

    status_t writeByteVectorInternal(const int8_t* data, size_t size);
    template<typename T>
    status_t readByteVectorInternal(std::vector<T>* val, size_t size) const;

    template<typename T, typename U>
    status_t            unsafeReadTypedVector(std::vector<T>* val,
                                              status_t(Parcel::*read_func)(U*) const) const;
    template<typename T>
    status_t            readNullableTypedVector(std::optional<std::vector<T>>* val,
                                                status_t(Parcel::*read_func)(T*) const) const;
    template<typename T>
    status_t            readNullableTypedVector(std::unique_ptr<std::vector<T>>* val,
                                                status_t(Parcel::*read_func)(T*) const) const __attribute__((deprecated("use std::optional version instead")));
    template<typename T>
    status_t            readTypedVector(std::vector<T>* val,
                                        status_t(Parcel::*read_func)(T*) const) const;
    template<typename T, typename U>
    status_t            unsafeWriteTypedVector(const std::vector<T>& val,
                                               status_t(Parcel::*write_func)(U));
    template<typename T>
    status_t            writeNullableTypedVector(const std::optional<std::vector<T>>& val,
                                                 status_t(Parcel::*write_func)(const T&));
    template<typename T>
    status_t            writeNullableTypedVector(const std::unique_ptr<std::vector<T>>& val,
                                                 status_t(Parcel::*write_func)(const T&)) __attribute__((deprecated("use std::optional version instead")));
    template<typename T>
    status_t            writeNullableTypedVector(const std::optional<std::vector<T>>& val,
                                                 status_t(Parcel::*write_func)(T));
    template<typename T>
    status_t            writeNullableTypedVector(const std::unique_ptr<std::vector<T>>& val,
                                                 status_t(Parcel::*write_func)(T)) __attribute__((deprecated("use std::optional version instead")));
    template<typename T>
    status_t            writeTypedVector(const std::vector<T>& val,
                                         status_t(Parcel::*write_func)(const T&));
    template<typename T>
    status_t            writeTypedVector(const std::vector<T>& val,
                                         status_t(Parcel::*write_func)(T));

    status_t            mError;
    uint8_t*            mData;
    size_t              mDataSize;
    size_t              mDataCapacity;
    mutable size_t      mDataPos;
    binder_size_t*      mObjects;
    size_t              mObjectsSize;
    size_t              mObjectsCapacity;
    mutable size_t      mNextObjectHint;
    mutable bool        mObjectsSorted;

    mutable bool        mRequestHeaderPresent;
    mutable size_t      mWorkSourceRequestHeaderPosition;

    mutable bool        mFdsKnown;
    mutable bool        mHasFds;
    bool                mAllowFds;

    // if this parcelable is involved in a secure transaction, force the
    // data to be overridden with zero when deallocated
    mutable bool        mDeallocZero;

    release_func        mOwner;

    // TODO(167966510): reserved for binder/version/stability
    void*               mReserved = reinterpret_cast<void*>(0xAAAAAAAA);

    class Blob {
    public:
        Blob();
        ~Blob();

        void clear();
        void release();
        inline size_t size() const { return mSize; }
        inline int fd() const { return mFd; }
        inline bool isMutable() const { return mMutable; }

    protected:
        void init(int fd, void* data, size_t size, bool isMutable);

        int mFd; // owned by parcel so not closed when released
        void* mData;
        size_t mSize;
        bool mMutable;
    };

    #if defined(__clang__)
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wweak-vtables"
    #endif

    // FlattenableHelperInterface and FlattenableHelper avoid generating a vtable entry in objects
    // following Flattenable template/protocol.
    class FlattenableHelperInterface {
    protected:
        ~FlattenableHelperInterface() { }
    public:
        virtual size_t getFlattenedSize() const = 0;
        virtual size_t getFdCount() const = 0;
        virtual status_t flatten(void* buffer, size_t size, int* fds, size_t count) const = 0;
        virtual status_t unflatten(void const* buffer, size_t size, int const* fds, size_t count) = 0;
    };

    #if defined(__clang__)
    #pragma clang diagnostic pop
    #endif

    // Concrete implementation of FlattenableHelperInterface that delegates virtual calls to the
    // specified class T implementing the Flattenable protocol. It "virtualizes" a compile-time
    // protocol.
    template<typename T>
    class FlattenableHelper : public FlattenableHelperInterface {
        friend class Parcel;
        const Flattenable<T>& val;
        explicit FlattenableHelper(const Flattenable<T>& _val) : val(_val) { }

    protected:
        ~FlattenableHelper() = default;
    public:
        virtual size_t getFlattenedSize() const {
            return val.getFlattenedSize();
        }
        virtual size_t getFdCount() const {
            return val.getFdCount();
        }
        virtual status_t flatten(void* buffer, size_t size, int* fds, size_t count) const {
            return val.flatten(buffer, size, fds, count);
        }
        virtual status_t unflatten(void const* buffer, size_t size, int const* fds, size_t count) {
            return const_cast<Flattenable<T>&>(val).unflatten(buffer, size, fds, count);
        }
    };
    status_t write(const FlattenableHelperInterface& val);
    status_t read(FlattenableHelperInterface& val) const;

public:
    class ReadableBlob : public Blob {
        friend class Parcel;
    public:
        inline const void* data() const { return mData; }
        inline void* mutableData() { return isMutable() ? mData : nullptr; }
    };

    class WritableBlob : public Blob {
        friend class Parcel;
    public:
        inline void* data() { return mData; }
    };

private:
    size_t mOpenAshmemSize;

public:
    // TODO: Remove once ABI can be changed.
    size_t getBlobAshmemSize() const;
    size_t getOpenAshmemSize() const;
};

// ---------------------------------------------------------------------------

template<typename T>
status_t Parcel::write(const Flattenable<T>& val) {
    const FlattenableHelper<T> helper(val);
    return write(helper);
}

template<typename T>
status_t Parcel::write(const LightFlattenable<T>& val) {
    size_t size(val.getFlattenedSize());
    if (!val.isFixedSize()) {
        if (size > INT32_MAX) {
            return BAD_VALUE;
        }
        status_t err = writeInt32(static_cast<int32_t>(size));
        if (err != NO_ERROR) {
            return err;
        }
    }
    if (size) {
        void* buffer = writeInplace(size);
        if (buffer == nullptr)
            return NO_MEMORY;
        return val.flatten(buffer, size);
    }
    return NO_ERROR;
}

template<typename T>
status_t Parcel::read(Flattenable<T>& val) const {
    FlattenableHelper<T> helper(val);
    return read(helper);
}

template<typename T>
status_t Parcel::read(LightFlattenable<T>& val) const {
    size_t size;
    if (val.isFixedSize()) {
        size = val.getFlattenedSize();
    } else {
        int32_t s;
        status_t err = readInt32(&s);
        if (err != NO_ERROR) {
            return err;
        }
        size = static_cast<size_t>(s);
    }
    if (size) {
        void const* buffer = readInplace(size);
        return buffer == nullptr ? NO_MEMORY :
                val.unflatten(buffer, size);
    }
    return NO_ERROR;
}

template<typename T>
status_t Parcel::writeVectorSize(const std::vector<T>& val) {
    if (val.size() > INT32_MAX) {
        return BAD_VALUE;
    }
    return writeInt32(static_cast<int32_t>(val.size()));
}

template<typename T>
status_t Parcel::writeVectorSize(const std::optional<std::vector<T>>& val) {
    if (!val) {
        return writeInt32(-1);
    }

    return writeVectorSize(*val);
}

template<typename T>
status_t Parcel::writeVectorSize(const std::unique_ptr<std::vector<T>>& val) {
    if (!val) {
        return writeInt32(-1);
    }

    return writeVectorSize(*val);
}

template<typename T>
status_t Parcel::resizeOutVector(std::vector<T>* val) const {
    int32_t size;
    status_t err = readInt32(&size);
    if (err != NO_ERROR) {
        return err;
    }

    if (size < 0) {
        return UNEXPECTED_NULL;
    }
    val->resize(size_t(size));
    return OK;
}

template<typename T>
status_t Parcel::resizeOutVector(std::optional<std::vector<T>>* val) const {
    int32_t size;
    status_t err = readInt32(&size);
    if (err != NO_ERROR) {
        return err;
    }

    val->reset();
    if (size >= 0) {
        val->emplace(size_t(size));
    }

    return OK;
}

template<typename T>
status_t Parcel::resizeOutVector(std::unique_ptr<std::vector<T>>* val) const {
    int32_t size;
    status_t err = readInt32(&size);
    if (err != NO_ERROR) {
        return err;
    }

    val->reset();
    if (size >= 0) {
        val->reset(new std::vector<T>(size_t(size)));
    }

    return OK;
}

template<typename T>
status_t Parcel::reserveOutVector(std::vector<T>* val, size_t* size) const {
    int32_t read_size;
    status_t err = readInt32(&read_size);
    if (err != NO_ERROR) {
        return err;
    }

    if (read_size < 0) {
        return UNEXPECTED_NULL;
    }
    *size = static_cast<size_t>(read_size);
    val->reserve(*size);
    return OK;
}

template<typename T>
status_t Parcel::reserveOutVector(std::optional<std::vector<T>>* val, size_t* size) const {
    int32_t read_size;
    status_t err = readInt32(&read_size);
    if (err != NO_ERROR) {
        return err;
    }

    if (read_size >= 0) {
        *size = static_cast<size_t>(read_size);
        val->emplace();
        (*val)->reserve(*size);
    } else {
        val->reset();
    }

    return OK;
}

template<typename T>
status_t Parcel::reserveOutVector(std::unique_ptr<std::vector<T>>* val,
                                  size_t* size) const {
    int32_t read_size;
    status_t err = readInt32(&read_size);
    if (err != NO_ERROR) {
        return err;
    }

    if (read_size >= 0) {
        *size = static_cast<size_t>(read_size);
        val->reset(new std::vector<T>());
        (*val)->reserve(*size);
    } else {
        val->reset();
    }

    return OK;
}

template<typename T>
status_t Parcel::readStrongBinder(sp<T>* val) const {
    sp<IBinder> tmp;
    status_t ret = readStrongBinder(&tmp);

    if (ret == OK) {
        *val = interface_cast<T>(tmp);

        if (val->get() == nullptr) {
            return UNKNOWN_ERROR;
        }
    }

    return ret;
}

template<typename T>
status_t Parcel::readNullableStrongBinder(sp<T>* val) const {
    sp<IBinder> tmp;
    status_t ret = readNullableStrongBinder(&tmp);

    if (ret == OK) {
        *val = interface_cast<T>(tmp);

        if (val->get() == nullptr && tmp.get() != nullptr) {
            ret = UNKNOWN_ERROR;
        }
    }

    return ret;
}

template<typename T, typename U>
status_t Parcel::unsafeReadTypedVector(
        std::vector<T>* val,
        status_t(Parcel::*read_func)(U*) const) const {
    int32_t size;
    status_t status = this->readInt32(&size);

    if (status != OK) {
        return status;
    }

    if (size < 0) {
        return UNEXPECTED_NULL;
    }

    if (val->max_size() < static_cast<size_t>(size)) {
        return NO_MEMORY;
    }

    val->resize(static_cast<size_t>(size));

    if (val->size() < static_cast<size_t>(size)) {
        return NO_MEMORY;
    }

    for (auto& v: *val) {
        status = (this->*read_func)(&v);

        if (status != OK) {
            return status;
        }
    }

    return OK;
}

template<typename T>
status_t Parcel::readTypedVector(std::vector<T>* val,
                                 status_t(Parcel::*read_func)(T*) const) const {
    return unsafeReadTypedVector(val, read_func);
}

template<typename T>
status_t Parcel::readNullableTypedVector(std::optional<std::vector<T>>* val,
                                         status_t(Parcel::*read_func)(T*) const) const {
    const size_t start = dataPosition();
    int32_t size;
    status_t status = readInt32(&size);
    val->reset();

    if (status != OK || size < 0) {
        return status;
    }

    setDataPosition(start);
    val->emplace();

    status = unsafeReadTypedVector(&**val, read_func);

    if (status != OK) {
       val->reset();
    }

    return status;
}

template<typename T>
status_t Parcel::readNullableTypedVector(std::unique_ptr<std::vector<T>>* val,
                                         status_t(Parcel::*read_func)(T*) const) const {
    const size_t start = dataPosition();
    int32_t size;
    status_t status = readInt32(&size);
    val->reset();

    if (status != OK || size < 0) {
        return status;
    }

    setDataPosition(start);
    val->reset(new std::vector<T>());

    status = unsafeReadTypedVector(val->get(), read_func);

    if (status != OK) {
        val->reset();
    }

    return status;
}

template<typename T, typename U>
status_t Parcel::unsafeWriteTypedVector(const std::vector<T>& val,
                                        status_t(Parcel::*write_func)(U)) {
    if (val.size() > std::numeric_limits<int32_t>::max()) {
        return BAD_VALUE;
    }

    status_t status = this->writeInt32(static_cast<int32_t>(val.size()));

    if (status != OK) {
        return status;
    }

    for (const auto& item : val) {
        status = (this->*write_func)(item);

        if (status != OK) {
            return status;
        }
    }

    return OK;
}

template<typename T>
status_t Parcel::writeTypedVector(const std::vector<T>& val,
                                  status_t(Parcel::*write_func)(const T&)) {
    return unsafeWriteTypedVector(val, write_func);
}

template<typename T>
status_t Parcel::writeTypedVector(const std::vector<T>& val,
                                  status_t(Parcel::*write_func)(T)) {
    return unsafeWriteTypedVector(val, write_func);
}

template<typename T>
status_t Parcel::writeNullableTypedVector(const std::optional<std::vector<T>>& val,
                                          status_t(Parcel::*write_func)(const T&)) {
    if (!val) {
        return this->writeInt32(-1);
    }

    return unsafeWriteTypedVector(*val, write_func);
}

template<typename T>
status_t Parcel::writeNullableTypedVector(const std::unique_ptr<std::vector<T>>& val,
                                          status_t(Parcel::*write_func)(const T&)) {
    if (val.get() == nullptr) {
        return this->writeInt32(-1);
    }

    return unsafeWriteTypedVector(*val, write_func);
}

template<typename T>
status_t Parcel::writeNullableTypedVector(const std::optional<std::vector<T>>& val,
                                          status_t(Parcel::*write_func)(T)) {
    if (!val) {
        return this->writeInt32(-1);
    }

    return unsafeWriteTypedVector(*val, write_func);
}

template<typename T>
status_t Parcel::writeNullableTypedVector(const std::unique_ptr<std::vector<T>>& val,
                                          status_t(Parcel::*write_func)(T)) {
    if (val.get() == nullptr) {
        return this->writeInt32(-1);
    }

    return unsafeWriteTypedVector(*val, write_func);
}

template<typename T>
status_t Parcel::readParcelableVector(std::vector<T>* val) const {
    return unsafeReadTypedVector<T, Parcelable>(val, &Parcel::readParcelable);
}

template<typename T>
status_t Parcel::readParcelableVector(std::optional<std::vector<std::optional<T>>>* val) const {
    const size_t start = dataPosition();
    int32_t size;
    status_t status = readInt32(&size);
    val->reset();

    if (status != OK || size < 0) {
        return status;
    }

    setDataPosition(start);
    val->emplace();

    using NullableT = std::optional<T>;
    status = unsafeReadTypedVector<NullableT, NullableT>(&**val, &Parcel::readParcelable);

    if (status != OK) {
        val->reset();
    }

    return status;
}

template<typename T>
status_t Parcel::readParcelableVector(std::unique_ptr<std::vector<std::unique_ptr<T>>>* val) const {
    const size_t start = dataPosition();
    int32_t size;
    status_t status = readInt32(&size);
    val->reset();

    if (status != OK || size < 0) {
        return status;
    }

    setDataPosition(start);
    val->reset(new std::vector<std::unique_ptr<T>>());

    using NullableT = std::unique_ptr<T>;
    status = unsafeReadTypedVector<NullableT, NullableT>(val->get(), &Parcel::readParcelable);

    if (status != OK) {
        val->reset();
    }

    return status;
}

template<typename T>
status_t Parcel::readParcelable(std::optional<T>* parcelable) const {
    const size_t start = dataPosition();
    int32_t present;
    status_t status = readInt32(&present);
    parcelable->reset();

    if (status != OK || !present) {
        return status;
    }

    setDataPosition(start);
    parcelable->emplace();

    status = readParcelable(&**parcelable);

    if (status != OK) {
        parcelable->reset();
    }

    return status;
}

template<typename T>
status_t Parcel::readParcelable(std::unique_ptr<T>* parcelable) const {
    const size_t start = dataPosition();
    int32_t present;
    status_t status = readInt32(&present);
    parcelable->reset();

    if (status != OK || !present) {
        return status;
    }

    setDataPosition(start);
    parcelable->reset(new T());

    status = readParcelable(parcelable->get());

    if (status != OK) {
        parcelable->reset();
    }

    return status;
}

template<typename T>
status_t Parcel::writeNullableParcelable(const std::optional<T>& parcelable) {
    return writeRawNullableParcelable(parcelable ? &*parcelable : nullptr);
}

template<typename T>
status_t Parcel::writeNullableParcelable(const std::unique_ptr<T>& parcelable) {
    return writeRawNullableParcelable(parcelable.get());
}

template<typename T>
status_t Parcel::writeParcelableVector(const std::vector<T>& val) {
    return unsafeWriteTypedVector<T,const Parcelable&>(val, &Parcel::writeParcelable);
}

template<typename T>
status_t Parcel::writeParcelableVector(const std::optional<std::vector<std::optional<T>>>& val) {
    if (!val) {
        return this->writeInt32(-1);
    }

    using NullableT = std::optional<T>;
    return unsafeWriteTypedVector<NullableT, const NullableT&>(*val, &Parcel::writeNullableParcelable);
}

template<typename T>
status_t Parcel::writeParcelableVector(const std::unique_ptr<std::vector<std::unique_ptr<T>>>& val) {
    if (val.get() == nullptr) {
        return this->writeInt32(-1);
    }

    return unsafeWriteTypedVector(*val, &Parcel::writeNullableParcelable<T>);
}

template<typename T>
status_t Parcel::writeParcelableVector(const std::shared_ptr<std::vector<std::unique_ptr<T>>>& val) {
    if (val.get() == nullptr) {
        return this->writeInt32(-1);
    }

    using NullableT = std::unique_ptr<T>;
    return unsafeWriteTypedVector<NullableT, const NullableT&>(*val, &Parcel::writeNullableParcelable);
}

template<typename T>
status_t Parcel::writeParcelableVector(const std::shared_ptr<std::vector<std::optional<T>>>& val) {
    if (val.get() == nullptr) {
        return this->writeInt32(-1);
    }

    using NullableT = std::optional<T>;
    return unsafeWriteTypedVector<NullableT, const NullableT&>(*val, &Parcel::writeNullableParcelable);
}

template<typename T, std::enable_if_t<std::is_same_v<typename std::underlying_type_t<T>,int32_t>, bool>>
status_t Parcel::writeEnum(const T& val) {
    return writeInt32(static_cast<int32_t>(val));
}
template<typename T, std::enable_if_t<std::is_same_v<typename std::underlying_type_t<T>,int64_t>, bool>>
status_t Parcel::writeEnum(const T& val) {
    return writeInt64(static_cast<int64_t>(val));
}

template<typename T, std::enable_if_t<std::is_enum_v<T> && std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool>>
status_t Parcel::writeEnumVector(const std::vector<T>& val) {
    return writeByteVectorInternal(reinterpret_cast<const int8_t*>(val.data()), val.size());
}
template<typename T, std::enable_if_t<std::is_enum_v<T> && std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool>>
status_t Parcel::writeEnumVector(const std::optional<std::vector<T>>& val) {
    if (!val) return writeInt32(-1);
    return writeByteVectorInternal(reinterpret_cast<const int8_t*>(val->data()), val->size());
}
template<typename T, std::enable_if_t<std::is_enum_v<T> && std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool>>
status_t Parcel::writeEnumVector(const std::unique_ptr<std::vector<T>>& val) {
    if (!val) return writeInt32(-1);
    return writeByteVectorInternal(reinterpret_cast<const int8_t*>(val->data()), val->size());
}
template<typename T, std::enable_if_t<std::is_enum_v<T> && !std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool>>
status_t Parcel::writeEnumVector(const std::vector<T>& val) {
    return writeTypedVector(val, &Parcel::writeEnum);
}
template<typename T, std::enable_if_t<std::is_enum_v<T> && !std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool>>
status_t Parcel::writeEnumVector(const std::optional<std::vector<T>>& val) {
    return writeNullableTypedVector(val, &Parcel::writeEnum);
}
template<typename T, std::enable_if_t<std::is_enum_v<T> && !std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool>>
status_t Parcel::writeEnumVector(const std::unique_ptr<std::vector<T>>& val) {
    return writeNullableTypedVector(val, &Parcel::writeEnum);
}

template<typename T, std::enable_if_t<std::is_same_v<typename std::underlying_type_t<T>,int32_t>, bool>>
status_t Parcel::readEnum(T* pArg) const {
    return readInt32(reinterpret_cast<int32_t *>(pArg));
}
template<typename T, std::enable_if_t<std::is_same_v<typename std::underlying_type_t<T>,int64_t>, bool>>
status_t Parcel::readEnum(T* pArg) const {
    return readInt64(reinterpret_cast<int64_t *>(pArg));
}

template<typename T>
inline status_t Parcel::readByteVectorInternal(std::vector<T>* val, size_t size) const {
  // readByteVectorInternal expects a vector that has been reserved (but not
  // resized) to have the provided size.
  const T* data = reinterpret_cast<const T*>(readInplace(size));
  if (!data) return BAD_VALUE;
  val->clear();
  val->insert(val->begin(), data, data+size);
  return NO_ERROR;
}

template<typename T, std::enable_if_t<std::is_enum_v<T> && std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool>>
status_t Parcel::readEnumVector(std::vector<T>* val) const {
    size_t size;
    if (status_t status = reserveOutVector(val, &size); status != OK) return status;
    return readByteVectorInternal(val, size);
}
template<typename T, std::enable_if_t<std::is_enum_v<T> && std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool>>
status_t Parcel::readEnumVector(std::optional<std::vector<T>>* val) const {
    size_t size;
    if (status_t status = reserveOutVector(val, &size); status != OK) return status;
    if (!*val) {
        // reserveOutVector does not create the out vector if size is < 0.
        // This occurs when writing a null Enum vector.
        return OK;
    }
    return readByteVectorInternal(&**val, size);
}
template<typename T, std::enable_if_t<std::is_enum_v<T> && std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool>>
status_t Parcel::readEnumVector(std::unique_ptr<std::vector<T>>* val) const {
    size_t size;
    if (status_t status = reserveOutVector(val, &size); status != OK) return status;
    if (val->get() == nullptr) {
        // reserveOutVector does not create the out vector if size is < 0.
        // This occurs when writing a null Enum vector.
        return OK;
    }
    return readByteVectorInternal(val->get(), size);
}
template<typename T, std::enable_if_t<std::is_enum_v<T> && !std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool>>
status_t Parcel::readEnumVector(std::vector<T>* val) const {
    return readTypedVector(val, &Parcel::readEnum);
}
template<typename T, std::enable_if_t<std::is_enum_v<T> && !std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool>>
status_t Parcel::readEnumVector(std::optional<std::vector<T>>* val) const {
    return readNullableTypedVector(val, &Parcel::readEnum);
}
template<typename T, std::enable_if_t<std::is_enum_v<T> && !std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool>>
status_t Parcel::readEnumVector(std::unique_ptr<std::vector<T>>* val) const {
    return readNullableTypedVector(val, &Parcel::readEnum);
}

// ---------------------------------------------------------------------------

inline TextOutput& operator<<(TextOutput& to, const Parcel& parcel)
{
    parcel.print(to);
    return to;
}

} // namespace android

// ---------------------------------------------------------------------------
