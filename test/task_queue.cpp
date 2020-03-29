//---------------------------------------------------------------------------//
// Copyright (c) 2011-2017 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE intrusive.task_queue

#include <nil/actor/intrusive/task_queue.hpp>

#include <boost/test/unit_test.hpp>

#include <memory>

#include <nil/actor/intrusive/singly_linked.hpp>

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

BOOST_AUTO_TEST_CASE(default_constructed) {
    ACTOR_REQUIRE_EQUAL(queue.empty(), true);
    ACTOR_REQUIRE_EQUAL(queue.total_task_size(), 0);
    ACTOR_REQUIRE_EQUAL(queue.peek(), nullptr);
    ACTOR_REQUIRE_EQUAL(queue.begin(), queue.end());
}

BOOST_AUTO_TEST_CASE(push_back) {
    queue.emplace_back(1);
    queue.push_back(inode_policy::unique_pointer {new inode(2)});
    queue.push_back(new inode(3));
    ACTOR_REQUIRE_EQUAL(deep_to_string(queue), "[1, 2, 3]");
}

BOOST_AUTO_TEST_CASE(lifo_conversion) {
    queue.lifo_append(new inode(3));
    queue.lifo_append(new inode(2));
    queue.lifo_append(new inode(1));
    queue.stop_lifo_append();
    ACTOR_REQUIRE_EQUAL(deep_to_string(queue), "[1, 2, 3]");
}

BOOST_AUTO_TEST_CASE(move_construct) {
    fill(queue, 1, 2, 3);
    queue_type q2 = std::move(queue);
    ACTOR_REQUIRE_EQUAL(queue.empty(), true);
    ACTOR_REQUIRE_EQUAL(q2.empty(), false);
    ACTOR_REQUIRE_EQUAL(deep_to_string(q2), "[1, 2, 3]");
}

BOOST_AUTO_TEST_CASE(move_assign) {
    queue_type q2 {policy};
    fill(q2, 1, 2, 3);
    queue = std::move(q2);
    ACTOR_REQUIRE_EQUAL(q2.empty(), true);
    ACTOR_REQUIRE_EQUAL(queue.empty(), false);
    ACTOR_REQUIRE_EQUAL(deep_to_string(queue), "[1, 2, 3]");
}

BOOST_AUTO_TEST_CASE(append) {
    queue_type q2 {policy};
    fill(queue, 1, 2, 3);
    fill(q2, 4, 5, 6);
    queue.append(q2);
    ACTOR_REQUIRE_EQUAL(q2.empty(), true);
    ACTOR_REQUIRE_EQUAL(queue.empty(), false);
    ACTOR_REQUIRE_EQUAL(deep_to_string(queue), "[1, 2, 3, 4, 5, 6]");
}

BOOST_AUTO_TEST_CASE(prepend) {
    queue_type q2 {policy};
    fill(queue, 1, 2, 3);
    fill(q2, 4, 5, 6);
    queue.prepend(q2);
    ACTOR_REQUIRE_EQUAL(q2.empty(), true);
    ACTOR_REQUIRE_EQUAL(queue.empty(), false);
    ACTOR_REQUIRE_EQUAL(deep_to_string(queue), "[4, 5, 6, 1, 2, 3]");
}

BOOST_AUTO_TEST_CASE(peek) {
    BOOST_CHECK_EQUAL(queue.peek(), nullptr);
    fill(queue, 1, 2, 3);
    BOOST_CHECK_EQUAL(queue.peek()->value, 1);
}

BOOST_AUTO_TEST_CASE(task_size) {
    fill(queue, 1, 2, 3);
    BOOST_CHECK_EQUAL(queue.total_task_size(), 6);
    fill(queue, 4, 5);
    BOOST_CHECK_EQUAL(queue.total_task_size(), 15);
    queue.clear();
    BOOST_CHECK_EQUAL(queue.total_task_size(), 0);
}

BOOST_AUTO_TEST_CASE(to_string) {
    BOOST_CHECK_EQUAL(deep_to_string(queue), "[]");
    fill(queue, 1, 2, 3, 4);
    BOOST_CHECK_EQUAL(deep_to_string(queue), "[1, 2, 3, 4]");
}

BOOST_AUTO_TEST_SUITE_END()
