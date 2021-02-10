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

#include <binder/Parcel.h>
#include <benchmark/benchmark.h>

// Usage: atest binderParcelBenchmark

// For static assert(false) we need a template version to avoid early failure.
// See: https://stackoverflow.com/questions/51523965/template-dependent-false
template <typename T>
constexpr bool dependent_false_v = false;

template <template <typename ...> class V, typename T, typename... Args>
void writeVector(android::Parcel &p, const V<T, Args...> &v) {
    if constexpr (std::is_same_v<T, bool>) {
        p.writeBoolVector(v);
    } else if constexpr (std::is_same_v<T, uint8_t>) {
        p.writeByteVector(v);
    } else if constexpr (std::is_same_v<T, char16_t>) {
        p.writeCharVector(v);
    } else if constexpr (std::is_same_v<T, int32_t>) {
        p.writeInt32Vector(v);
    } else if constexpr (std::is_same_v<T, int64_t>) {
        p.writeInt64Vector(v);
    } else {
        static_assert(dependent_false_v<V<T>>);
    }
}

template <template <typename ...> class V, typename T, typename... Args>
void readVector(android::Parcel &p, V<T, Args...> *v) {
    if constexpr (std::is_same_v<T, bool>) {
        p.readBoolVector(v);
    } else if constexpr (std::is_same_v<T, uint8_t>) {
        p.readByteVector(v);
    } else if constexpr (std::is_same_v<T, char16_t>) {
        p.readCharVector(v);
    } else if constexpr (std::is_same_v<T, int32_t>) {
        p.readInt32Vector(v);
    } else if constexpr (std::is_same_v<T, int64_t>) {
        p.readInt64Vector(v);
    } else {
        static_assert(dependent_false_v<V<T>>);
    }
}

// Construct a series of args { 1 << 0, 1 << 1, ..., 1 << 10 }
static void VectorArgs(benchmark::internal::Benchmark* b) {
    for (int i = 0; i < 10; ++i) {
        b->Args({1 << i});
    }
}

template <typename T>
static void BM_ParcelVector(benchmark::State& state) {
    const size_t elements = state.range(0);

    std::vector<T> v1(elements);
    std::vector<T> v2(elements);
    android::Parcel p;
    while (state.KeepRunning()) {
        p.setDataPosition(0);
        writeVector(p, v1);

        p.setDataPosition(0);
        readVector(p, &v2);

        benchmark::DoNotOptimize(v2[0]);
        benchmark::ClobberMemory();
    }
    state.SetComplexityN(elements);
}

/*
  Parcel vector write than read.
  The read and write vectors are fixed, no resizing required.

  Results on Crosshatch Pixel 3XL

  #BM_BoolVector/1         44 ns      44 ns     15630626
  #BM_BoolVector/2         54 ns      54 ns     12900340
  #BM_BoolVector/4         73 ns      72 ns      9749841
  #BM_BoolVector/8        107 ns     107 ns      6503326
  #BM_BoolVector/16       186 ns     185 ns      3773627
  #BM_BoolVector/32       337 ns     336 ns      2083877
  #BM_BoolVector/64       607 ns     605 ns      1154113
  #BM_BoolVector/128     1155 ns    1151 ns       608128
  #BM_BoolVector/256     2259 ns    2253 ns       310973
  #BM_BoolVector/512     4469 ns    4455 ns       157277
  #BM_ByteVector/1         41 ns      41 ns     16837425
  #BM_ByteVector/2         41 ns      41 ns     16820726
  #BM_ByteVector/4         38 ns      38 ns     18217813
  #BM_ByteVector/8         38 ns      38 ns     18290298
  #BM_ByteVector/16        38 ns      38 ns     18117817
  #BM_ByteVector/32        38 ns      38 ns     18172385
  #BM_ByteVector/64        41 ns      41 ns     16950055
  #BM_ByteVector/128       53 ns      53 ns     13170749
  #BM_ByteVector/256       69 ns      69 ns     10113626
  #BM_ByteVector/512      106 ns     106 ns      6561936
  #BM_CharVector/1         38 ns      38 ns     18074831
  #BM_CharVector/2         40 ns      40 ns     17206266
  #BM_CharVector/4         50 ns      50 ns     13785944
  #BM_CharVector/8         67 ns      67 ns     10223316
  #BM_CharVector/16        96 ns      96 ns      7297285
  #BM_CharVector/32       156 ns     155 ns      4484845
  #BM_CharVector/64       277 ns     276 ns      2536003
  #BM_CharVector/128      520 ns     518 ns      1347070
  #BM_CharVector/256     1006 ns    1003 ns       695952
  #BM_CharVector/512     1976 ns    1970 ns       354673
  #BM_Int32Vector/1        41 ns      41 ns     16951262
  #BM_Int32Vector/2        41 ns      41 ns     16916883
  #BM_Int32Vector/4        41 ns      41 ns     16761373
  #BM_Int32Vector/8        42 ns      42 ns     16553179
  #BM_Int32Vector/16       43 ns      43 ns     16200362
  #BM_Int32Vector/32       55 ns      54 ns     12724454
  #BM_Int32Vector/64       70 ns      69 ns     10049223
  #BM_Int32Vector/128     107 ns     107 ns      6525796
  #BM_Int32Vector/256     179 ns     178 ns      3922563
  #BM_Int32Vector/512     324 ns     323 ns      2160653
  #BM_Int64Vector/1        41 ns      41 ns     16909470
  #BM_Int64Vector/2        41 ns      41 ns     16740788
  #BM_Int64Vector/4        42 ns      42 ns     16564197
  #BM_Int64Vector/8        43 ns      42 ns     16284082
  #BM_Int64Vector/16       54 ns      54 ns     12839474
  #BM_Int64Vector/32       69 ns      69 ns     10011010
  #BM_Int64Vector/64      107 ns     106 ns      6557956
  #BM_Int64Vector/128     177 ns     177 ns      3925618
  #BM_Int64Vector/256     324 ns     323 ns      2163321
  #BM_Int64Vector/512     613 ns     611 ns      1140418
*/

static void BM_BoolVector(benchmark::State& state) {
    BM_ParcelVector<bool>(state);
}

static void BM_ByteVector(benchmark::State& state) {
    BM_ParcelVector<uint8_t>(state);
}

static void BM_CharVector(benchmark::State& state) {
    BM_ParcelVector<char16_t>(state);
}

static void BM_Int32Vector(benchmark::State& state) {
    BM_ParcelVector<int32_t>(state);
}

static void BM_Int64Vector(benchmark::State& state) {
    BM_ParcelVector<int64_t>(state);
}

BENCHMARK(BM_BoolVector)->Apply(VectorArgs);
BENCHMARK(BM_ByteVector)->Apply(VectorArgs);
BENCHMARK(BM_CharVector)->Apply(VectorArgs);
BENCHMARK(BM_Int32Vector)->Apply(VectorArgs);
BENCHMARK(BM_Int64Vector)->Apply(VectorArgs);

BENCHMARK_MAIN();
