//---------------------------------------------------------------------------//
//
// Copyright (c) 2024 Martun Karapetyan <martun@nil.foundation>
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

#define BOOST_TEST_MODULE thread_pool_test

#include <vector>
#include <cstdint>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/actor/core/thread_pool.hpp>
#include <nil/actor/core/parallelization_utils.hpp>


BOOST_AUTO_TEST_SUITE(thread_pool_test_suite)

BOOST_AUTO_TEST_CASE(vector_multiplication_test) {
    boost::unit_test::unit_test_log_t::instance().set_threshold_level( boost::unit_test::log_messages );
    //boost::unit_test::framework::instance().set_report_level(boost::unit_test::log_silent);
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
        BOOST_CHECK_EQUAL(v[i], i * i);
    }
}

BOOST_AUTO_TEST_SUITE_END()
