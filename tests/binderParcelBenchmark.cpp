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

  #BM_BoolVector/1         40 ns      40 ns     17261011
  #BM_BoolVector/2         46 ns      46 ns     15029619
  #BM_BoolVector/4         65 ns      64 ns     10888021
  #BM_BoolVector/8        114 ns     114 ns      6130937
  #BM_BoolVector/16       179 ns     179 ns      3902462
  #BM_BoolVector/32       328 ns     327 ns      2138812
  #BM_BoolVector/64       600 ns     598 ns      1169414
  #BM_BoolVector/128     1168 ns    1165 ns       601281
  #BM_BoolVector/256     2288 ns    2281 ns       305737
  #BM_BoolVector/512     4535 ns    4521 ns       154668
  #BM_ByteVector/1         53 ns      52 ns     13212196
  #BM_ByteVector/2         53 ns      53 ns     13194050
  #BM_ByteVector/4         50 ns      50 ns     13768037
  #BM_ByteVector/8         50 ns      50 ns     13890210
  #BM_ByteVector/16        50 ns      50 ns     13897305
  #BM_ByteVector/32        51 ns      51 ns     13679862
  #BM_ByteVector/64        54 ns      53 ns     12988544
  #BM_ByteVector/128       64 ns      64 ns     10921227
  #BM_ByteVector/256       82 ns      81 ns      8542549
  #BM_ByteVector/512      118 ns     118 ns      5862931
  #BM_CharVector/1         32 ns      32 ns     21783579
  #BM_CharVector/2         38 ns      38 ns     18200971
  #BM_CharVector/4         53 ns      53 ns     13111785
  #BM_CharVector/8         80 ns      80 ns      8698331
  #BM_CharVector/16       159 ns     159 ns      4390738
  #BM_CharVector/32       263 ns     262 ns      2667310
  #BM_CharVector/64       486 ns     485 ns      1441118
  #BM_CharVector/128      937 ns     934 ns       749006
  #BM_CharVector/256     1848 ns    1843 ns       379537
  #BM_CharVector/512     3650 ns    3639 ns       191713
  #BM_Int32Vector/1        31 ns      31 ns     22104147
  #BM_Int32Vector/2        38 ns      38 ns     18075471
  #BM_Int32Vector/4        53 ns      52 ns     13249969
  #BM_Int32Vector/8        80 ns      80 ns      8719798
  #BM_Int32Vector/16      161 ns     160 ns      4350096
  #BM_Int32Vector/32      271 ns     270 ns      2591896
  #BM_Int32Vector/64      499 ns     498 ns      1406201
  #BM_Int32Vector/128     948 ns     945 ns       740052
  #BM_Int32Vector/256    1855 ns    1849 ns       379127
  #BM_Int32Vector/512    3665 ns    3653 ns       191533
  #BM_Int64Vector/1        31 ns      31 ns     22388370
  #BM_Int64Vector/2        38 ns      38 ns     18300347
  #BM_Int64Vector/4        53 ns      53 ns     13137818
  #BM_Int64Vector/8        81 ns      81 ns      8599613
  #BM_Int64Vector/16      167 ns     166 ns      4195953
  #BM_Int64Vector/32      280 ns     280 ns      2499271
  #BM_Int64Vector/64      523 ns     522 ns      1341380
  #BM_Int64Vector/128     991 ns     988 ns       707437
  #BM_Int64Vector/256    1940 ns    1934 ns       361704
  #BM_Int64Vector/512    3843 ns    3831 ns       183204
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
