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

#define BOOST_TEST_MODULE wdrr_dynamic_multiplexed_queue_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>

#include <memory>

#include <nil/actor/deep_to_string.hpp>

#include <nil/actor/intrusive/drr_queue.hpp>
#include <nil/actor/intrusive/singly_linked.hpp>
#include <nil/actor/intrusive/wdrr_dynamic_multiplexed_queue.hpp>

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

    struct nested_inode_policy {
        using mapped_type = inode;

        using task_size_type = int;

        using deficit_type = int;

        using deleter_type = std::default_delete<mapped_type>;

        using unique_pointer = std::unique_ptr<mapped_type, deleter_type>;

        static inline task_size_type task_size(const mapped_type &) {
            return 1;
        }

        std::unique_ptr<int> queue_id;

        nested_inode_policy(int i) : queue_id(new int(i)) {
            // nop
        }

        nested_inode_policy(nested_inode_policy &&) = default;

        nested_inode_policy &operator=(nested_inode_policy &&) = default;
    };

    struct inode_policy {
        using mapped_type = inode;

        using key_type = int;

        using task_size_type = int;

        using deficit_type = int;

        using deleter_type = std::default_delete<mapped_type>;

        using unique_pointer = std::unique_ptr<mapped_type, deleter_type>;

        using queue_type = drr_queue<nested_inode_policy>;

        using queue_map_type = std::map<key_type, queue_type>;

        static inline key_type id_of(const inode &x) {
            return x.value % 3;
        }

        static inline bool enabled(const queue_type &) {
            return true;
        }

        deficit_type quantum(const queue_type &q, deficit_type x) {
            return enable_priorities && *q.policy().queue_id == 0 ? 2 * x : x;
        }

        bool enable_priorities = false;
    };

    using queue_type = wdrr_dynamic_multiplexed_queue<inode_policy>;

    using nested_queue_type = inode_policy::queue_type;

    struct fixture {
        inode_policy policy;
        queue_type queue {policy};

        int fill(queue_type &) {
            return 0;
        }

        template<class T, class... Ts>
        int fill(queue_type &q, T x, Ts... xs) {
            return (q.emplace_back(x) ? 1 : 0) + fill(q, xs...);
        }

        std::string fetch(int quantum) {
            std::string result;
            auto f = [&](int id, nested_queue_type &q, inode &x) {
                BOOST_CHECK_EQUAL(id, *q.policy().queue_id);
                if (!result.empty()) {
                    result += ',';
                }
                result += to_string(id);
                result += ':';
                result += to_string(x);
                return task_result::resume;
            };
            queue.new_round(quantum, f);
            return result;
        }

        void make_queues() {
            for (int i = 0; i < 3; ++i) {
                queue.queues().emplace(i, nested_inode_policy {i});
            }
        }
    };

}    // namespace

BOOST_FIXTURE_TEST_SUITE(wdrr_dynamic_multiplexed_queue_tests, fixture)

BOOST_AUTO_TEST_CASE(default_constructed_test) {
    BOOST_REQUIRE_EQUAL(queue.empty(), true);
}

BOOST_AUTO_TEST_CASE(dropping_test) {
    BOOST_REQUIRE_EQUAL(queue.empty(), true);
    BOOST_REQUIRE_EQUAL(fill(queue, 1, 2, 3, 4, 5, 6, 7, 8, 9, 12), 0);
    BOOST_REQUIRE_EQUAL(queue.empty(), true);
}

BOOST_AUTO_TEST_CASE(new_round_test) {
    make_queues();
    fill(queue, 1, 2, 3, 4, 5, 6, 7, 8, 9, 12);
    BOOST_REQUIRE_EQUAL(queue.empty(), false);
    BOOST_CHECK_EQUAL(fetch(1), "0:3,1:1,2:2");
    BOOST_REQUIRE_EQUAL(queue.empty(), false);
    BOOST_CHECK_EQUAL(fetch(9), "0:6,0:9,0:12,1:4,1:7,2:5,2:8");
    BOOST_REQUIRE_EQUAL(queue.empty(), true);
}

BOOST_AUTO_TEST_CASE(priorities_test) {
    make_queues();
    queue.policy().enable_priorities = true;
    fill(queue, 1, 2, 3, 4, 5, 6, 7, 8, 9);
    // Allow f to consume 2 items from the high priority and 1 item otherwise.
    BOOST_CHECK_EQUAL(fetch(1), "0:3,0:6,1:1,2:2");
    BOOST_REQUIRE_EQUAL(queue.empty(), false);
    // Drain the high-priority queue with one item left per other queue.
    BOOST_CHECK_EQUAL(fetch(1), "0:9,1:4,2:5");
    BOOST_REQUIRE_EQUAL(queue.empty(), false);
    // Drain queue.
    BOOST_CHECK_EQUAL(fetch(1000), "1:7,2:8");
    BOOST_REQUIRE_EQUAL(queue.empty(), true);
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
    make_queues();
    BOOST_CHECK_EQUAL(queue_to_string(), "");
    queue.emplace_back(1);
    BOOST_CHECK_EQUAL(queue_to_string(), "1");
    queue.emplace_back(2);
    BOOST_CHECK_EQUAL(queue_to_string(), "1, 2");
    queue.emplace_back(3);
    // Lists are iterated in order and 3 is stored in the first queue for
    // `x mod 3 == 0` values.
    BOOST_CHECK_EQUAL(queue_to_string(), "3, 1, 2");
    queue.emplace_back(4);
    BOOST_CHECK_EQUAL(queue_to_string(), "3, 1, 4, 2");
}

BOOST_AUTO_TEST_CASE(to_string_test) {
    make_queues();
    BOOST_CHECK_EQUAL(deep_to_string(queue), "[]");
    fill(queue, 1, 2, 3, 4);
    BOOST_CHECK_EQUAL(deep_to_string(queue), "[3, 1, 4, 2]");
}

BOOST_AUTO_TEST_SUITE_END()
