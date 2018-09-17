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

def replaceFileTags(path, content):
    print("Updating", path)
    with open(path, "r+") as f:
        lines = f.readlines()

        start = lines.index("// @START\n")
        end = lines.index("// @END\n")

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

    header = ""
    source = ""

    for pretty, cpp in data_types:
        header += "/**\n"
        header += " * Writes " + cpp + " value to the next location in a non-null parcel.\n"
        header += " */\n"
        header += "binder_status_t AParcel_write" + pretty + "(AParcel* parcel, " + cpp + " value);\n\n"
        source += "binder_status_t AParcel_write" + pretty + "(AParcel* parcel, " + cpp + " value) {\n"
        source += "    status_t status = (*parcel)->write" + pretty + "(value);\n"
        source += "    return PruneStatusT(status);\n"
        source += "}\n\n"

    for pretty, cpp in data_types:
        header += "/**\n"
        header += " * Reads into " + cpp + " value from the next location in a non-null parcel.\n"
        header += " */\n"
        header += "binder_status_t AParcel_read" + pretty + "(const AParcel* parcel, " + cpp + "* value);\n\n"
        source += "binder_status_t AParcel_read" + pretty + "(const AParcel* parcel, " + cpp + "* value) {\n"
        source += "    status_t status = (*parcel)->read" + pretty + "(value);\n"
        source += "    return PruneStatusT(status);\n"
        source += "}\n\n"

    replaceFileTags(ROOT + "include_ndk/android/binder_parcel.h", header)
    replaceFileTags(ROOT + "parcel.cpp", source)

    print("Updating DONE.")

if __name__ == "__main__":
    main()
