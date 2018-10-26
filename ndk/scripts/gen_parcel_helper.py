#!/usr/bin/env python3

# Copyright (C) 2018 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import sys

# list (pretty, cpp)
data_types = [
    ("Int32", "int32_t"),
    ("Uint32", "uint32_t"),
    ("Int64", "int64_t"),
    ("Uint64", "uint64_t"),
    ("Float", "float"),
    ("Double", "double"),
    ("Bool", "bool"),
    ("Char", "char16_t"),
    ("Byte", "int8_t"),
]

non_contiguously_addressable = {"Bool"}

def replaceFileTags(path, content, start_tag, end_tag):
    print("Updating", path)
    with open(path, "r+") as f:
        lines = f.readlines()

        start = lines.index("// @" + start_tag + "\n")
        end = lines.index("// @" + end_tag + "\n")

        if end <= start or start < 0 or end < 0:
            print("Failed to find tags in", path)
            exit(1)

        f.seek(0)
        f.write("".join(lines[:start+1]) + content + "".join(lines[end:]))
        f.truncate()

def main():
    if len(sys.argv) != 1:
        print("No arguments.")
        exit(1)

    ABT = os.environ.get('ANDROID_BUILD_TOP', None)
    if ABT is None:
        print("Can't get ANDROID_BUILD_TOP. Lunch?")
        exit(1)
    ROOT = ABT + "/frameworks/native/libs/binder/ndk/"

    print("Updating auto-generated code")

    pre_header = ""
    header = ""
    source = ""
    cpp_helper = ""

    for pretty, cpp in data_types:
        header += "/**\n"
        header += " * Writes " + cpp + " value to the next location in a non-null parcel.\n"
        header += " */\n"
        header += "binder_status_t AParcel_write" + pretty + "(AParcel* parcel, " + cpp + " value) __INTRODUCED_IN(29);\n\n"
        source += "binder_status_t AParcel_write" + pretty + "(AParcel* parcel, " + cpp + " value) {\n"
        source += "    status_t status = parcel->get()->write" + pretty + "(value);\n"
        source += "    return PruneStatusT(status);\n"
        source += "}\n\n"

    for pretty, cpp in data_types:
        header += "/**\n"
        header += " * Reads into " + cpp + " value from the next location in a non-null parcel.\n"
        header += " */\n"
        header += "binder_status_t AParcel_read" + pretty + "(const AParcel* parcel, " + cpp + "* value) __INTRODUCED_IN(29);\n\n"
        source += "binder_status_t AParcel_read" + pretty + "(const AParcel* parcel, " + cpp + "* value) {\n"
        source += "    status_t status = parcel->get()->read" + pretty + "(value);\n"
        source += "    return PruneStatusT(status);\n"
        source += "}\n\n"

    for pretty, cpp in data_types:
        nca = pretty in non_contiguously_addressable

        arg_type = "const " + cpp + "* value"
        if nca: arg_type = "const void* arrayData, AParcel_" + pretty.lower() + "ArrayGetter getter"
        args = "value, length"
        if nca: args = "arrayData, getter, length, &Parcel::write" + pretty

        header += "/**\n"
        header += " * Writes an array of " + cpp + " to the next location in a non-null parcel.\n"
        header += " */\n"
        header += "binder_status_t AParcel_write" + pretty + "Array(AParcel* parcel, " + arg_type + ", size_t length) __INTRODUCED_IN(29);\n\n"
        source += "binder_status_t AParcel_write" + pretty + "Array(AParcel* parcel, " + arg_type + ", size_t length) {\n"
        source += "    return WriteArray<" + cpp + ">(parcel, " + args + ");\n";
        source += "}\n\n"

    for pretty, cpp in data_types:
        nca = pretty in non_contiguously_addressable

        extra_getter_args = ""
        if nca: extra_getter_args = ", size_t index"
        getter_return = cpp + "*"
        if nca: getter_return = cpp
        getter_array_data = "void* arrayData"
        if nca: getter_array_data = "const void* arrayData"

        getter_type = "AParcel_" + pretty.lower() + "ArrayGetter"
        setter_type = "AParcel_" + pretty.lower() + "ArraySetter"

        pre_header += "/**\n"
        pre_header += " * This is called to get the underlying data from an arrayData object.\n"
        pre_header += " *\n"
        pre_header += " * This will never be called for an empty array.\n"
        pre_header += " */\n"
        pre_header += "typedef " + getter_return + " (*" + getter_type + ")(" + getter_array_data + extra_getter_args + ");\n\n"

        if nca:
            pre_header += "/**\n"
            pre_header += " * This is called to set an underlying value in an arrayData object at index.\n"
            pre_header += " */\n"
            pre_header += "typedef void (*" + setter_type + ")(void* arrayData, size_t index, " + cpp + " value);\n\n"

        read_using = "getter"
        if nca: read_using = "setter"
        read_type = getter_type
        if nca: read_type = setter_type

        arguments = ["const AParcel* parcel"]
        arguments += ["void** arrayData"]
        arguments += ["AParcel_arrayReallocator reallocator"]
        arguments += [read_type + " " + read_using]
        arguments = ", ".join(arguments)

        header += "/**\n"
        header += " * Reads an array of " + cpp + " from the next location in a non-null parcel.\n"
        header += " */\n"
        header += "binder_status_t AParcel_read" + pretty + "Array(" + arguments + ") __INTRODUCED_IN(29);\n\n"
        source += "binder_status_t AParcel_read" + pretty + "Array(" + arguments + ") {\n"
        additional_args = ""
        if nca: additional_args = ", &Parcel::read" + pretty
        source += "    return ReadArray<" + cpp + ">(parcel, arrayData, reallocator, " + read_using + additional_args + ");\n";
        source += "}\n\n"

        cpp_helper += "/**\n"
        cpp_helper += " * Writes a vector of " + cpp + " to the next location in a non-null parcel.\n"
        cpp_helper += " */\n"
        cpp_helper += "inline binder_status_t AParcel_writeVector(AParcel* parcel, const std::vector<" + cpp + ">& vec) {\n"
        write_args = "vec.data()"
        if nca: write_args = "static_cast<const void*>(&vec), AParcel_stdVectorGetter<" + cpp + ">"
        cpp_helper += "    return AParcel_write" + pretty + "Array(parcel, " + write_args + ", vec.size());\n"
        cpp_helper += "}\n\n"

        cpp_helper += "/**\n"
        cpp_helper += " * Reads a vector of " + cpp + " from the next location in a non-null parcel.\n"
        cpp_helper += " */\n"
        cpp_helper += "inline binder_status_t AParcel_readVector(const AParcel* parcel, std::vector<" + cpp + ">* vec) {\n"
        cpp_helper += "    void* vectorData = static_cast<void*>(vec);\n"
        read_args = []
        read_args += ["parcel"]
        read_args += ["&vectorData"]
        read_args += ["&AParcel_stdVectorReallocator<" + cpp + ">"]
        read_args += ["AParcel_stdVector" + read_using.capitalize() + "<" + cpp + ">"]
        cpp_helper += "    return AParcel_read" + pretty + "Array(" + ", ".join(read_args) + ");\n"
        cpp_helper += "}\n\n"

    replaceFileTags(ROOT + "include_ndk/android/binder_parcel.h", pre_header, "START-PRIMITIVE-VECTOR-GETTERS", "END-PRIMITIVE-VECTOR-GETTERS")
    replaceFileTags(ROOT + "include_ndk/android/binder_parcel.h", header, "START-PRIMITIVE-READ-WRITE", "END-PRIMITIVE-READ-WRITE")
    replaceFileTags(ROOT + "parcel.cpp", source, "START", "END")
    replaceFileTags(ROOT + "include_ndk/android/binder_parcel_utils.h", cpp_helper, "START", "END")

    print("Updating DONE.")

if __name__ == "__main__":
    main()
