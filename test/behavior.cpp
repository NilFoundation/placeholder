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

#define BOOST_TEST_MODULE behavior_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>

#include <functional>

#include <nil/actor/config.hpp>

#include <nil/actor/send.hpp>
#include <nil/actor/behavior.hpp>
#include <nil/actor/spawner.hpp>
#include <nil/actor/message_handler.hpp>
#include <nil/actor/event_based_actor.hpp>
#include <nil/actor/spawner_config.hpp>
#include <nil/actor/make_type_erased_tuple_view.hpp>

using namespace nil::actor;
using namespace std;

using hi_atom = atom_constant<atom("hi")>;
using ho_atom = atom_constant<atom("ho")>;

namespace {

    class nocopy_fun {
    public:
        nocopy_fun() = default;

        nocopy_fun(nocopy_fun &&) = default;

        nocopy_fun &operator=(nocopy_fun &&) = default;

        nocopy_fun(const nocopy_fun &) = delete;

        nocopy_fun &operator=(const nocopy_fun &) = delete;

        int operator()(int x, int y) {
            return x + y;
        }
    };

    struct fixture {
        message m1 = make_message(1);
        message m2 = make_message(1, 2);
        message m3 = make_message(1, 2, 3);
    };

}    // namespace

BOOST_FIXTURE_TEST_SUITE(behavior_tests, fixture)

BOOST_AUTO_TEST_CASE(default_construct_test) {
    behavior f;
    BOOST_CHECK(f(m1) == none);
    BOOST_CHECK(f(m2) == none);
    BOOST_CHECK(f(m3) == none);
}

BOOST_AUTO_TEST_CASE(nocopy_function_object_test) {
    behavior f {nocopy_fun {}};
    BOOST_CHECK(f(m1) == none);
    BOOST_CHECK_EQUAL(to_string(f(m2)), "*(3)");
    BOOST_CHECK(f(m3) == none);
}

BOOST_AUTO_TEST_CASE(single_lambda_construct_test) {
    behavior f {[](int x) { return x + 1; }};
    BOOST_CHECK_EQUAL(to_string(f(m1)), "*(2)");
    BOOST_CHECK(f(m2) == none);
    BOOST_CHECK(f(m3) == none);
}

BOOST_AUTO_TEST_CASE(multiple_lambda_construct_test) {
    behavior f {[](int x) { return x + 1; }, [](int x, int y) { return x * y; }};
    BOOST_CHECK_EQUAL(to_string(f(m1)), "*(2)");
    BOOST_CHECK_EQUAL(to_string(f(m2)), "*(2)");
    BOOST_CHECK(f(m3) == none);
}

BOOST_AUTO_TEST_CASE(become_empty_behavior_test) {
    spawner_config cfg {};
    spawner sys {cfg};
    auto make_bhvr = [](event_based_actor *self) -> behavior { return {[=](int) { self->become(behavior {}); }}; };
    anon_send(sys.spawn(make_bhvr), int {5});
}

BOOST_AUTO_TEST_SUITE_END()
