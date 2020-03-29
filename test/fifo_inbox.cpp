//---------------------------------------------------------------------------//
// Copyright (c) 2011-2017 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE intrusive.fifo_inbox

#include <nil/actor/intrusive/fifo_inbox.hpp>

#include <boost/test/unit_test.hpp>

#include <memory>

#include <nil/actor/intrusive/drr_queue.hpp>
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

        using deficit_type = int;

        using deleter_type = std::default_delete<mapped_type>;

        using unique_pointer = std::unique_ptr<mapped_type, deleter_type>;

        using queue_type = drr_queue<inode_policy>;

        static constexpr task_size_type task_size(const inode &) noexcept {
            return 1;
        }
    };

    using inbox_type = fifo_inbox<inode_policy>;

    struct fixture {
        inode_policy policy;
        inbox_type inbox {policy};

        void fill(inbox_type &) {
            // nop
        }

        template<class T, class... Ts>
        void fill(inbox_type &i, T x, Ts... xs) {
            i.emplace_back(x);
            fill(i, xs...);
        }

        std::string fetch() {
            std::string result;
            auto f = [&](inode &x) {
                result += to_string(x);
                return task_result::resume;
            };
            inbox.new_round(1000, f);
            return result;
        }

        std::string close_and_fetch() {
            std::string result;
            auto f = [&](inode &x) {
                result += to_string(x);
                return task_result::resume;
            };
            inbox.close();
            inbox.queue().new_round(1000, f);
            return result;
        }
    };

}    // namespace

BOOST_FIXTURE_TEST_SUITE(fifo_inbox_tests, fixture)

BOOST_AUTO_TEST_CASE(default_constructed) {
    BOOST_REQUIRE_EQUAL(inbox.empty(), true);
}

BOOST_AUTO_TEST_CASE(push_front) {
    fill(inbox, 1, 2, 3);
    BOOST_REQUIRE_EQUAL(close_and_fetch(), "123");
    BOOST_REQUIRE_EQUAL(inbox.closed(), true);
}

BOOST_AUTO_TEST_CASE(push_after_close) {
    inbox.close();
    auto res = inbox.push_back(new inode(0));
    BOOST_REQUIRE_EQUAL(res, inbox_result::queue_closed);
}

BOOST_AUTO_TEST_CASE(unblock) {
    BOOST_REQUIRE_EQUAL(inbox.try_block(), true);
    auto res = inbox.push_back(new inode(0));
    BOOST_REQUIRE_EQUAL(res, inbox_result::unblocked_reader);
    res = inbox.push_back(new inode(1));
    BOOST_REQUIRE_EQUAL(res, inbox_result::success);
    BOOST_REQUIRE_EQUAL(close_and_fetch(), "01");
}

BOOST_AUTO_TEST_CASE(await) {
    std::mutex mx;
    std::condition_variable cv;
    std::thread t {[&] { inbox.synchronized_emplace_back(mx, cv, 1); }};
    inbox.synchronized_await(mx, cv);
    BOOST_REQUIRE_EQUAL(close_and_fetch(), "1");
    t.join();
}

BOOST_AUTO_TEST_CASE(timed_await) {
    std::mutex mx;
    std::condition_variable cv;
    auto tout = std::chrono::system_clock::now();
    tout += std::chrono::microseconds(1);
    auto res = inbox.synchronized_await(mx, cv, tout);
    BOOST_REQUIRE_EQUAL(res, false);
    fill(inbox, 1);
    res = inbox.synchronized_await(mx, cv, tout);
    BOOST_REQUIRE_EQUAL(res, true);
    BOOST_CHECK_EQUAL(fetch(), "1");
    tout += std::chrono::hours(1000);
    std::thread t {[&] { inbox.synchronized_emplace_back(mx, cv, 2); }};
    res = inbox.synchronized_await(mx, cv, tout);
    BOOST_REQUIRE_EQUAL(res, true);
    BOOST_REQUIRE_EQUAL(close_and_fetch(), "2");
    t.join();
}
BOOST_AUTO_TEST_SUITE_END()
