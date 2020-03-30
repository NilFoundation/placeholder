//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE detail.ringbuffer

#include <nil/actor/detail/ringbuffer.hpp>

#include <nil/actor/test/dsl.hpp>

#include <algorithm>

using namespace nil::actor;

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<template<typename...> class P, typename... T>
            struct print_log_value<P<T...>> {
                void operator()(std::ostream &, P<T...> const &) {
                }
            };

            template<template<typename, std::size_t> class P, typename T, std::size_t S>
            struct print_log_value<P<T, S>> {
                void operator()(std::ostream &, P<T, S> const &) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

namespace {

    static constexpr size_t buf_size = 64;

    using int_ringbuffer = detail::ringbuffer<int, buf_size>;

    std::vector<int> consumer(int_ringbuffer &buf, size_t num) {
        std::vector<int> result;
        for (size_t i = 0; i < num; ++i) {
            buf.wait_nonempty();
            result.emplace_back(buf.front());
            buf.pop_front();
        }
        return result;
    }

    void producer(int_ringbuffer &buf, int first, int last) {
        for (auto i = first; i != last; ++i)
            buf.push_back(std::move(i));
    }

    struct fixture {
        int_ringbuffer buf;
    };

}    // namespace

BOOST_FIXTURE_TEST_SUITE(ringbuffer_tests, fixture)

BOOST_AUTO_TEST_CASE(construction) {
    BOOST_CHECK_EQUAL(buf.empty(), true);
    BOOST_CHECK_EQUAL(buf.full(), false);
    BOOST_CHECK_EQUAL(buf.size(), 0u);
}

BOOST_AUTO_TEST_CASE(push_back) {
    BOOST_TEST_MESSAGE("add one element");
    buf.push_back(42);
    BOOST_CHECK_EQUAL(buf.empty(), false);
    BOOST_CHECK_EQUAL(buf.full(), false);
    BOOST_CHECK_EQUAL(buf.size(), 1u);
    BOOST_CHECK_EQUAL(buf.front(), 42);
    BOOST_TEST_MESSAGE("remove element");
    buf.pop_front();
    BOOST_CHECK_EQUAL(buf.empty(), true);
    BOOST_CHECK_EQUAL(buf.full(), false);
    BOOST_CHECK_EQUAL(buf.size(), 0u);
    BOOST_TEST_MESSAGE("fill buffer");
    for (int i = 0; i < static_cast<int>(buf_size - 1); ++i)
        buf.push_back(std::move(i));
    BOOST_CHECK_EQUAL(buf.empty(), false);
    BOOST_CHECK_EQUAL(buf.full(), true);
    BOOST_CHECK_EQUAL(buf.size(), buf_size - 1);
    BOOST_CHECK_EQUAL(buf.front(), 0);
}

BOOST_AUTO_TEST_CASE(get_all) {
    using array_type = std::array<int, buf_size>;
    using vector_type = std::vector<int>;
    array_type tmp;
    auto fetch_all = [&] {
        auto i = tmp.begin();
        auto e = buf.get_all(i);
        return vector_type(i, e);
    };
    BOOST_TEST_MESSAGE("add five element");
    for (int i = 0; i < 5; ++i)
        buf.push_back(std::move(i));
    BOOST_CHECK_EQUAL(buf.empty(), false);
    BOOST_CHECK_EQUAL(buf.full(), false);
    BOOST_CHECK_EQUAL(buf.size(), 5u);
    BOOST_CHECK_EQUAL(buf.front(), 0);
    BOOST_TEST_MESSAGE("drain elements");
    BOOST_CHECK_EQUAL(fetch_all(), vector_type({0, 1, 2, 3, 4}));
    BOOST_CHECK_EQUAL(buf.empty(), true);
    BOOST_CHECK_EQUAL(buf.full(), false);
    BOOST_CHECK_EQUAL(buf.size(), 0u);
    BOOST_TEST_MESSAGE("add 60 elements (wraps around)");
    vector_type expected;
    for (int i = 0; i < 60; ++i) {
        expected.push_back(i);
        buf.push_back(std::move(i));
    }
    BOOST_CHECK_EQUAL(buf.size(), 60u);
    BOOST_CHECK_EQUAL(fetch_all(), expected);
    BOOST_CHECK_EQUAL(buf.empty(), true);
    BOOST_CHECK_EQUAL(buf.full(), false);
    BOOST_CHECK_EQUAL(buf.size(), 0u);
}

BOOST_AUTO_TEST_CASE(concurrent_access) {
    std::vector<std::thread> producers;
    producers.emplace_back(producer, std::ref(buf), 0, 100);
    producers.emplace_back(producer, std::ref(buf), 100, 200);
    producers.emplace_back(producer, std::ref(buf), 200, 300);
    auto vec = consumer(buf, 300);
    std::sort(vec.begin(), vec.end());
    BOOST_CHECK(std::is_sorted(vec.begin(), vec.end()));
    BOOST_CHECK_EQUAL(vec.size(), 300u);
    BOOST_CHECK_EQUAL(vec.front(), 0);
    BOOST_CHECK_EQUAL(vec.back(), 299);
    for (auto &t : producers)
        t.join();
}

BOOST_AUTO_TEST_SUITE_END()
