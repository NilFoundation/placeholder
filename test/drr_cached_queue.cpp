//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt for Boost License or
// http://opensource.org/licenses/BSD-3-Clause for BSD 3-Clause License
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE drr_cached_queue_test

#include <memory>

#include <boost/test/unit_test.hpp>

#include <nil/actor/deep_to_string.hpp>

#include <nil/actor/intrusive/singly_linked.hpp>
#include <nil/actor/intrusive/drr_cached_queue.hpp>

using namespace nil::actor;
using namespace nil::actor::intrusive;

namespace {

    struct inode : singly_linked<inode> {
        int value;

        inode(int x = 0) : value(x) {
            // nop
        }
    };

    std::string to_string(const inode &x) {
        return std::to_string(x.value);
    }

    struct inode_policy {
        using mapped_type = inode;

        using task_size_type = int;

        using deficit_type = int;

        using deleter_type = std::default_delete<mapped_type>;

        using unique_pointer = std::unique_ptr<mapped_type, deleter_type>;

        static inline task_size_type task_size(const mapped_type &) noexcept {
            return 1;
        }
    };

    using queue_type = drr_cached_queue<inode_policy>;

    struct fixture {
        inode_policy policy;
        queue_type queue {policy};

        template<class Queue>
        void fill(Queue &) {
            // nop
        }

        template<class Queue, class T, class... Ts>
        void fill(Queue &q, T x, Ts... xs) {
            q.emplace_back(x);
            fill(q, xs...);
        }
    };

}    // namespace

BOOST_FIXTURE_TEST_SUITE(drr_cached_queue_tests, fixture)

BOOST_AUTO_TEST_CASE(default_constructed_test) {
    BOOST_REQUIRE_EQUAL(queue.empty(), true);
    BOOST_REQUIRE_EQUAL(queue.deficit(), 0);
    BOOST_REQUIRE_EQUAL(queue.total_task_size(), 0);
    BOOST_REQUIRE_EQUAL(queue.peek(), nullptr);
}

BOOST_AUTO_TEST_CASE(new_round_test) {
    // Define a function object for consuming even numbers.
    std::string fseq;
    auto f = [&](inode &x) -> task_result {
        if ((x.value & 0x01) == 1) {
            return task_result::skip;
        }
        fseq += to_string(x);
        return task_result::resume;
    };
    // Define a function object for consuming odd numbers.
    std::string gseq;
    auto g = [&](inode &x) -> task_result {
        if ((x.value & 0x01) == 0) {
            return task_result::skip;
        }
        gseq += to_string(x);
        return task_result::resume;
    };
    fill(queue, 1, 2, 3, 4, 5, 6, 7, 8, 9);
    // Allow f to consume 2, 4, and 6.
    auto round_result = queue.new_round(3, f);
    BOOST_CHECK(round_result == make_new_round_result(true));
    BOOST_CHECK_EQUAL(fseq, "246");
    BOOST_CHECK_EQUAL(queue.deficit(), 0);
    // Allow g to consume 1, 3, 5, and 7.
    round_result = queue.new_round(4, g);
    BOOST_CHECK(round_result == make_new_round_result(true));
    BOOST_CHECK_EQUAL(gseq, "1357");
    BOOST_CHECK_EQUAL(queue.deficit(), 0);
}

BOOST_AUTO_TEST_CASE(skipping_test) {
    // Define a function object for consuming even numbers.
    std::string seq;
    auto f = [&](inode &x) -> task_result {
        if ((x.value & 0x01) == 1) {
            return task_result::skip;
        }
        seq += to_string(x);
        return task_result::resume;
    };
    BOOST_TEST_MESSAGE("make a round on an empty queue");
    BOOST_CHECK(queue.new_round(10, f) == make_new_round_result(false));
    BOOST_TEST_MESSAGE("make a round on a queue with only odd numbers (skip all)");
    fill(queue, 1, 3, 5);
    BOOST_CHECK(queue.new_round(10, f) == make_new_round_result(false));
    BOOST_TEST_MESSAGE("make a round on a queue with an even number at the front");
    fill(queue, 2);
    BOOST_CHECK(queue.new_round(10, f) == make_new_round_result(true));
    BOOST_CHECK_EQUAL(seq, "2");
    BOOST_TEST_MESSAGE("make a round on a queue with an even number in between");
    fill(queue, 7, 9, 4, 11, 13);
    BOOST_CHECK(queue.new_round(10, f) == make_new_round_result(true));
    BOOST_CHECK_EQUAL(seq, "24");
    BOOST_TEST_MESSAGE("make a round on a queue with an even number at the back");
    fill(queue, 15, 17, 6);
    BOOST_CHECK(queue.new_round(10, f) == make_new_round_result(true));
    BOOST_CHECK_EQUAL(seq, "246");
}

BOOST_AUTO_TEST_CASE(take_front_test) {
    std::string seq;
    fill(queue, 1, 2, 3, 4, 5, 6);
    auto f = [&](inode &x) {
        seq += to_string(x);
        return task_result::resume;
    };
    BOOST_CHECK_EQUAL(queue.deficit(), 0);
    while (!queue.empty()) {
        auto ptr = queue.take_front();
        f(*ptr);
    }
    BOOST_CHECK_EQUAL(seq, "123456");
    fill(queue, 5, 4, 3, 2, 1);
    while (!queue.empty()) {
        auto ptr = queue.take_front();
        f(*ptr);
    }
    BOOST_CHECK_EQUAL(seq, "12345654321");
    BOOST_CHECK_EQUAL(queue.deficit(), 0);
}

BOOST_AUTO_TEST_CASE(alternating_consumer_test) {
    using fun_type = std::function<task_result(inode &)>;
    fun_type f;
    fun_type g;
    fun_type *selected = &f;
    // Define a function object for consuming even numbers.
    std::string seq;
    f = [&](inode &x) -> task_result {
        if ((x.value & 0x01) == 1) {
            return task_result::skip;
        }
        seq += to_string(x);
        selected = &g;
        return task_result::resume;
    };
    // Define a function object for consuming odd numbers.
    g = [&](inode &x) -> task_result {
        if ((x.value & 0x01) == 0) {
            return task_result::skip;
        }
        seq += to_string(x);
        selected = &f;
        return task_result::resume;
    };
    /// Define a function object that alternates between f and g.
    auto h = [&](inode &x) { return (*selected)(x); };
    // Fill and consume queue, h leaves 9 in the cache since it reads (odd, even)
    // sequences and no odd value to read after 7 is available.
    fill(queue, 1, 2, 3, 4, 5, 6, 7, 8, 9);
    auto round_result = queue.new_round(1000, h);
    BOOST_CHECK(round_result == make_new_round_result(true));
    BOOST_CHECK_EQUAL(seq, "21436587");
    BOOST_CHECK_EQUAL(queue.deficit(), 0);
    BOOST_CHECK_EQUAL(deep_to_string(queue.cache()), "[9]");
}

BOOST_AUTO_TEST_CASE(peek_all_test) {
    auto queue_to_string = [&] {
        std::string str;
        auto peek_fun = [&](const inode &x) {
            if (!str.empty()) {
                str += ", ";
            }
            str += std::to_string(x.value);
        };
        queue.peek_all(peek_fun);
        return str;
    };
    BOOST_CHECK_EQUAL(queue_to_string(), "");
    queue.emplace_back(2);
    BOOST_CHECK_EQUAL(queue_to_string(), "2");
    queue.cache().emplace_back(1);
    BOOST_CHECK_EQUAL(queue_to_string(), "2");
    queue.emplace_back(3);
    BOOST_CHECK_EQUAL(queue_to_string(), "2, 3");
    queue.flush_cache();
    BOOST_CHECK_EQUAL(queue_to_string(), "1, 2, 3");
}

BOOST_AUTO_TEST_CASE(to_string_test) {
    BOOST_CHECK_EQUAL(deep_to_string(queue), "[]");
    fill(queue, 3, 4);
    BOOST_CHECK_EQUAL(deep_to_string(queue), "[3, 4]");
    fill(queue.cache(), 1, 2);
    BOOST_CHECK_EQUAL(deep_to_string(queue), "[3, 4]");
    queue.flush_cache();
    BOOST_CHECK_EQUAL(deep_to_string(queue), "[1, 2, 3, 4]");
}

BOOST_AUTO_TEST_SUITE_END()
