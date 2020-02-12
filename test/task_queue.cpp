//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt for Boost License or
// http://opensource.org/licenses/BSD-3-Clause for BSD 3-Clause License
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE task_queue_test

#include <boost/test/unit_test.hpp>

#include <memory>

#include <nil/actor/deep_to_string.hpp>

#include <nil/actor/intrusive/singly_linked.hpp>
#include <nil/actor/intrusive/task_queue.hpp>

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

        using deleter_type = std::default_delete<mapped_type>;

        using unique_pointer = std::unique_ptr<mapped_type, deleter_type>;

        static inline task_size_type task_size(const mapped_type &x) {
            return x.value;
        }
    };

    using queue_type = task_queue<inode_policy>;

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

BOOST_FIXTURE_TEST_SUITE(task_queue_tests, fixture)

BOOST_AUTO_TEST_CASE(default_constructed_test) {
    BOOST_REQUIRE_EQUAL(queue.empty(), true);
    BOOST_REQUIRE_EQUAL(queue.total_task_size(), 0);
    BOOST_REQUIRE_EQUAL(queue.peek(), nullptr);
    BOOST_REQUIRE(queue.begin() == queue.end());
}

BOOST_AUTO_TEST_CASE(push_back_test) {
    queue.emplace_back(1);
    queue.push_back(inode_policy::unique_pointer {new inode(2)});
    queue.push_back(new inode(3));
    BOOST_REQUIRE_EQUAL(deep_to_string(queue), "[1, 2, 3]");
}

BOOST_AUTO_TEST_CASE(lifo_conversion_test) {
    queue.lifo_append(new inode(3));
    queue.lifo_append(new inode(2));
    queue.lifo_append(new inode(1));
    queue.stop_lifo_append();
    BOOST_REQUIRE_EQUAL(deep_to_string(queue), "[1, 2, 3]");
}

BOOST_AUTO_TEST_CASE(move_construct_test) {
    fill(queue, 1, 2, 3);
    queue_type q2 = std::move(queue);
    BOOST_REQUIRE_EQUAL(queue.empty(), true);
    BOOST_REQUIRE_EQUAL(q2.empty(), false);
    BOOST_REQUIRE_EQUAL(deep_to_string(q2), "[1, 2, 3]");
}

BOOST_AUTO_TEST_CASE(move_assign_test) {
    queue_type q2 {policy};
    fill(q2, 1, 2, 3);
    queue = std::move(q2);
    BOOST_REQUIRE_EQUAL(q2.empty(), true);
    BOOST_REQUIRE_EQUAL(queue.empty(), false);
    BOOST_REQUIRE_EQUAL(deep_to_string(queue), "[1, 2, 3]");
}

BOOST_AUTO_TEST_CASE(append_test) {
    queue_type q2 {policy};
    fill(queue, 1, 2, 3);
    fill(q2, 4, 5, 6);
    queue.append(q2);
    BOOST_REQUIRE_EQUAL(q2.empty(), true);
    BOOST_REQUIRE_EQUAL(queue.empty(), false);
    BOOST_REQUIRE_EQUAL(deep_to_string(queue), "[1, 2, 3, 4, 5, 6]");
}

BOOST_AUTO_TEST_CASE(prepend_test) {
    queue_type q2 {policy};
    fill(queue, 1, 2, 3);
    fill(q2, 4, 5, 6);
    queue.prepend(q2);
    BOOST_REQUIRE_EQUAL(q2.empty(), true);
    BOOST_REQUIRE_EQUAL(queue.empty(), false);
    BOOST_REQUIRE_EQUAL(deep_to_string(queue), "[4, 5, 6, 1, 2, 3]");
}

BOOST_AUTO_TEST_CASE(peek_test) {
    BOOST_CHECK_EQUAL(queue.peek(), nullptr);
    fill(queue, 1, 2, 3);
    BOOST_CHECK_EQUAL(queue.peek()->value, 1);
}

BOOST_AUTO_TEST_CASE(task_size_test) {
    fill(queue, 1, 2, 3);
    BOOST_CHECK_EQUAL(queue.total_task_size(), 6);
    fill(queue, 4, 5);
    BOOST_CHECK_EQUAL(queue.total_task_size(), 15);
    queue.clear();
    BOOST_CHECK_EQUAL(queue.total_task_size(), 0);
}

BOOST_AUTO_TEST_CASE(to_string_test) {
    BOOST_CHECK_EQUAL(deep_to_string(queue), "[]");
    fill(queue, 1, 2, 3, 4);
    BOOST_CHECK_EQUAL(deep_to_string(queue), "[1, 2, 3, 4]");
}

BOOST_AUTO_TEST_SUITE_END()
