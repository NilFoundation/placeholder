//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE policy.categorized

#include <nil/actor/policy/categorized.hpp>

#include <nil/actor/test/dsl.hpp>

#include <nil/actor/intrusive/drr_queue.hpp>
#include <nil/actor/intrusive/fifo_inbox.hpp>
#include <nil/actor/intrusive/wdrr_dynamic_multiplexed_queue.hpp>
#include <nil/actor/intrusive/wdrr_fixed_multiplexed_queue.hpp>
#include <nil/actor/policy/downstream_messages.hpp>
#include <nil/actor/policy/normal_messages.hpp>
#include <nil/actor/policy/upstream_messages.hpp>
#include <nil/actor/policy/urgent_messages.hpp>
#include <nil/actor/unit.hpp>

using namespace nil::actor;

namespace {

    using urgent_queue = intrusive::drr_queue<policy::urgent_messages>;

    using normal_queue = intrusive::drr_queue<policy::normal_messages>;

    using upstream_queue = intrusive::drr_queue<policy::upstream_messages>;

    using downstream_queue = intrusive::wdrr_dynamic_multiplexed_queue<policy::downstream_messages>;

    struct mailbox_policy {
        using deficit_type = size_t;

        using mapped_type = mailbox_element;

        using unique_pointer = mailbox_element_ptr;

        using queue_type = intrusive::wdrr_fixed_multiplexed_queue<policy::categorized, urgent_queue, normal_queue,
                                                                   upstream_queue, downstream_queue>;
    };

    using mailbox_type = intrusive::fifo_inbox<mailbox_policy>;

    struct fixture {};

    struct consumer {
        std::vector<int> ints;

        template<class Key, class Queue>
        intrusive::task_result operator()(const Key &, const Queue &, const mailbox_element &x) {
            if (!x.content().match_elements<int>())
                BOOST_FAIL("unexpected message: " << x.content());
            ints.emplace_back(x.content().get_as<int>(0));
            return intrusive::task_result::resume;
        }

        template<class Key, class Queue, class... Ts>
        intrusive::task_result operator()(const Key &, const Queue &, const Ts &...) {
            BOOST_FAIL("unexpected message type");    // << typeid(Ts).name());
            return intrusive::task_result::resume;
        }
    };

}    // namespace

BOOST_FIXTURE_TEST_SUITE(categorized_tests, fixture)

BOOST_AUTO_TEST_CASE(priorities) {
    mailbox_type mbox {unit, unit, unit, unit, unit};
    mbox.push_back(make_mailbox_element(nullptr, make_message_id(), {}, 123));
    mbox.push_back(make_mailbox_element(nullptr, make_message_id(message_priority::high), {}, 456));
    consumer f;
    mbox.new_round(1000, f);
    BOOST_CHECK_EQUAL(f.ints, std::vector<int>({456, 123}));
}

BOOST_AUTO_TEST_SUITE_END()
