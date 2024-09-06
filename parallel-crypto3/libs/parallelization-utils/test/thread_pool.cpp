//---------------------------------------------------------------------------//
<<<<<<<< HEAD:crypto3/libs/block/test/md4.cpp
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
========
// 
// Copyright (c) 2024 Martun Karapetyan <martun@nil.foundation>
>>>>>>>> parallel-crypto3/migration:parallel-crypto3/libs/parallelization-utils/test/thread_pool.cpp
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

<<<<<<<< HEAD:crypto3/libs/block/test/md4.cpp
#define BOOST_TEST_MODULE md4_cipher_test

#include <iostream>
#include <unordered_map>
========
#define BOOST_TEST_MODULE thread_pool_test

#include <vector>
#include <cstdint>
>>>>>>>> parallel-crypto3/migration:parallel-crypto3/libs/parallelization-utils/test/thread_pool.cpp

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

<<<<<<<< HEAD:crypto3/libs/block/test/md4.cpp
#include <nil/crypto3/block/md4.hpp>

#include <nil/crypto3/block/algorithm/encrypt.hpp>
#include <nil/crypto3/block/algorithm/decrypt.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::block;

struct state_adder {
    template<typename T>
    void operator()(T &s1, T const &s2) {
        typedef typename T::size_type size_type;
        size_type n = (s2.size() < s1.size() ? s2.size() : s1.size());
        for (typename T::size_type i = 0; i < n; ++i) {
            s1[i] += s2[i];
        }
    }
};

BOOST_TEST_DONT_PRINT_LOG_VALUE(md4::block_type)

BOOST_AUTO_TEST_SUITE(md4_test_suite)

BOOST_AUTO_TEST_CASE(md4_single_block_encrypt1) {
========
#include <nil/actor/core/thread_pool.hpp>
#include <nil/actor/core/parallelization_utils.hpp>


BOOST_AUTO_TEST_SUITE(thread_pool_test_suite)

BOOST_AUTO_TEST_CASE(vector_multiplication_test) {
    size_t size = 131072;

    std::vector<size_t> v(size);

    for (std::size_t i = 0; i < size; ++i)
        v[i] = i;

    nil::crypto3::wait_for_all(nil::crypto3::parallel_run_in_chunks<void>(
        size,
        [&v](std::size_t begin, std::size_t end) {
            for (std::size_t i = begin; i < end; ++i) {
                v[i] *= v[i];
            }
        }, nil::crypto3::ThreadPool::PoolLevel::HIGH));

    for (std::size_t i = 0; i < size; ++i) {
        BOOST_CHECK(v[i] == i * i);
    }
>>>>>>>> parallel-crypto3/migration:parallel-crypto3/libs/parallelization-utils/test/thread_pool.cpp
}

BOOST_AUTO_TEST_SUITE_END()