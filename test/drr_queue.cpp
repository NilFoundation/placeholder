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

#define BOOST_TEST_MODULE drr_queue_test

#include <memory>

#include <boost/test/unit_test.hpp>

#include <nil/actor/deep_to_string.hpp>
#include <nil/actor/intrusive/singly_linked.hpp>
#include <nil/actor/intrusive/drr_queue.hpp>

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

        static inline task_size_type task_size(const mapped_type &x) {
            return x.value;
        }
    };

    using queue_type = drr_queue<inode_policy>;

    struct fixture {
        inode_policy policy;
        queue_type queue {policy};

        void fill(queue_type &) {
            // nop
        }

        template<class T, class... Ts>
        void fill(queue_type &q, T x, Ts... xs) {
            q.emplace_back(x);
            fill(q, xs...);
        }
    };

}    // namespace

BOOST_FIXTURE_TEST_SUITE(drr_queue_tests, fixture)

BOOST_AUTO_TEST_CASE(default_constructed_test) {
    BOOST_REQUIRE_EQUAL(queue.empty(), true);
    BOOST_REQUIRE_EQUAL(queue.deficit(), 0);
    BOOST_REQUIRE_EQUAL(queue.total_task_size(), 0);
    BOOST_REQUIRE_EQUAL(queue.peek(), nullptr);
    BOOST_REQUIRE_EQUAL(queue.next(), nullptr);
    BOOST_REQUIRE(queue.begin() == queue.end());
}

BOOST_AUTO_TEST_CASE(inc_deficit_test) {
    // Increasing the deficit does nothing as long as the queue is empty.
    queue.inc_deficit(100);
    BOOST_REQUIRE_EQUAL(queue.deficit(), 0);
    // Increasing the deficit must work on non-empty queues.
    fill(queue, 1);
    queue.inc_deficit(100);
    BOOST_REQUIRE_EQUAL(queue.deficit(), 100);
    // Deficit must drop back down to 0 once the queue becomes empty.
    queue.next();
    BOOST_REQUIRE_EQUAL(queue.deficit(), 0);
}

BOOST_AUTO_TEST_CASE(new_round_test) {
    std::string seq;
    fill(queue, 1, 2, 3, 4, 5, 6);
    auto f = [&](inode &x) {
        seq += to_string(x);
        return task_result::resume;
    };
    // Allow f to consume 1, 2, and 3 with a leftover deficit of 1.
    auto round_result = queue.new_round(7, f);
    BOOST_CHECK(round_result == make_new_round_result(true));
    BOOST_CHECK_EQUAL(seq, "123");
    BOOST_CHECK_EQUAL(queue.deficit(), 1);
    // Allow f to consume 4 and 5 with a leftover deficit of 0.
    round_result = queue.new_round(8, f);
    BOOST_CHECK(round_result == make_new_round_result(true));
    BOOST_CHECK_EQUAL(seq, "12345");
    BOOST_CHECK_EQUAL(queue.deficit(), 0);
    // Allow f to consume 6 with a leftover deficit of 0 (queue is empty).
    round_result = queue.new_round(1000, f);
    BOOST_CHECK(round_result == make_new_round_result(true));
    BOOST_CHECK_EQUAL(seq, "123456");
    BOOST_CHECK_EQUAL(queue.deficit(), 0);
    // new_round on an empty queue does nothing.
    round_result = queue.new_round(1000, f);
    BOOST_CHECK(round_result == make_new_round_result(false));
    BOOST_CHECK_EQUAL(seq, "123456");
    BOOST_CHECK_EQUAL(queue.deficit(), 0);
}

BOOST_AUTO_TEST_CASE(next_test) {
    std::string seq;
    fill(queue, 1, 2, 3, 4, 5, 6);
    auto f = [&](inode &x) {
        seq += to_string(x);
        return task_result::resume;
    };
    auto take = [&] {
        queue.flush_cache();
        queue.inc_deficit(queue.peek()->value);
        return queue.next();
    };
    while (!queue.empty()) {
        auto ptr = take();
        f(*ptr);
    }
    BOOST_CHECK_EQUAL(seq, "123456");
    fill(queue, 5, 4, 3, 2, 1);
    while (!queue.empty()) {
        auto ptr = take();
        f(*ptr);
    }
    BOOST_CHECK_EQUAL(seq, "12345654321");
    BOOST_CHECK_EQUAL(queue.deficit(), 0);
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
    queue.emplace_back(1);
    BOOST_CHECK_EQUAL(queue_to_string(), "1");
    queue.emplace_back(2);
    BOOST_CHECK_EQUAL(queue_to_string(), "1, 2");
    queue.emplace_back(3);
    BOOST_CHECK_EQUAL(queue_to_string(), "1, 2, 3");
    queue.emplace_back(4);
    BOOST_CHECK_EQUAL(queue_to_string(), "1, 2, 3, 4");
}

BOOST_AUTO_TEST_CASE(to_string_test) {
    BOOST_CHECK_EQUAL(deep_to_string(queue), "[]");
    fill(queue, 1, 2, 3, 4);
    BOOST_CHECK_EQUAL(deep_to_string(queue), "[1, 2, 3, 4]");
}

BOOST_AUTO_TEST_SUITE_END()
