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

#define BOOST_TEST_MODULE match_test

#include <boost/test/unit_test.hpp>

#include <functional>

#include <nil/actor/config.hpp>
#include <nil/actor/message_builder.hpp>
#include <nil/actor/message_handler.hpp>
#include <nil/actor/make_type_erased_tuple_view.hpp>

using namespace nil::actor;

using hi_atom = atom_constant<atom("hi")>;
using ho_atom = atom_constant<atom("ho")>;

namespace {

    using rtti_pair = std::pair<uint16_t, const std::type_info *>;

    std::string to_string(const rtti_pair &x) {
        std::string result = "(";
        result += std::to_string(x.first);
        result += ", ";
        result += x.second != nullptr ? x.second->name() : "<null>";
        result += ")";
        return result;
    }

    struct fixture {
        using array_type = std::array<bool, 4>;

        fixture() {
            reset();
        }

        void reset() {
            for (auto &x : invoked) {
                x = false;
            }
        }

        template<class... Ts>
        ptrdiff_t invoke(message_handler expr, Ts... xs) {
            auto msg1 = make_message(xs...);
            auto msg2 = message_builder {}.append_all(xs...).move_to_message();
            auto msg3 = make_type_erased_tuple_view(xs...);
            BOOST_CHECK(to_string(msg1) == to_string(msg2));
            BOOST_CHECK(to_string(msg1) == to_string(msg3));
            BOOST_CHECK_EQUAL(msg1.type_token(), msg2.type_token());
            BOOST_CHECK_EQUAL(msg1.type_token(), msg3.type_token());
            std::vector<std::string> msg1_types;
            std::vector<std::string> msg2_types;
            std::vector<std::string> msg3_types;
            for (size_t i = 0; i < msg1.size(); ++i) {
                msg1_types.push_back(to_string(msg1.type(i)));
                msg2_types.push_back(to_string(msg2.type(i)));
                msg3_types.push_back(to_string(msg3.type(i)));
            }
            BOOST_CHECK(msg1_types == msg2_types);
            BOOST_CHECK(msg1_types == msg3_types);
            std::set<ptrdiff_t> results;
            process(results, expr, msg1, msg2, msg3);
            if (results.size() > 1) {
                BOOST_ERROR("different results reported: " << deep_to_string(results));
                return -2;
            }
            return *results.begin();
        }

        void process(std::set<ptrdiff_t> &, message_handler &) {
            // end of recursion
        }

        template<class T, class... Ts>
        void process(std::set<ptrdiff_t> &results, message_handler &expr, T &x, Ts &... xs) {
            expr(x);
            results.insert(invoked_res());
            reset();
            process(results, expr, xs...);
        }

        ptrdiff_t invoked_res() {
            auto first = begin(invoked);
            auto last = end(invoked);
            auto i = std::find(first, last, true);
            if (i != last) {
                BOOST_REQUIRE_EQUAL(std::count(i, last, true), 1u);
                return std::distance(first, i);
            }
            return -1;
        }

        array_type invoked;
    };

}    // namespace

BOOST_FIXTURE_TEST_SUITE(atom_constants_tests, fixture)

BOOST_AUTO_TEST_CASE(atom_constants_test) {
    message_handler expr {[&](hi_atom) { invoked[0] = true; }, [&](ho_atom) { invoked[1] = true; }};
    BOOST_CHECK_EQUAL(invoke(expr, atom_value {ok_atom::value}), -1);
    BOOST_CHECK_EQUAL(invoke(expr, atom_value {hi_atom::value}), 0);
    BOOST_CHECK_EQUAL(invoke(expr, atom_value {ho_atom::value}), 1);
}

BOOST_AUTO_TEST_CASE(manual_matching_test) {
    using foo_atom = atom_constant<atom("foo")>;
    using bar_atom = atom_constant<atom("bar")>;
    auto msg1 = make_message(foo_atom::value, 42);
    auto msg2 = make_message(bar_atom::value, 42);
    BOOST_TEST_MESSAGE("check individual message elements");
    BOOST_CHECK((msg1.match_element<int>(1)));
    BOOST_CHECK((msg2.match_element<int>(1)));
    BOOST_CHECK((msg1.match_element<foo_atom>(0)));
    BOOST_CHECK((!msg2.match_element<foo_atom>(0)));
    BOOST_CHECK((!msg1.match_element<bar_atom>(0)));
    BOOST_CHECK((msg2.match_element<bar_atom>(0)));
    BOOST_TEST_MESSAGE("check matching whole tuple");
    BOOST_CHECK((msg1.match_elements<foo_atom, int>()));
    BOOST_CHECK(!(msg2.match_elements<foo_atom, int>()));
    BOOST_CHECK(!(msg1.match_elements<bar_atom, int>()));
    BOOST_CHECK((msg2.match_elements<bar_atom, int>()));
    BOOST_CHECK((msg1.match_elements<atom_value, int>()));
    BOOST_CHECK((msg2.match_elements<atom_value, int>()));
    BOOST_CHECK(!(msg1.match_elements<atom_value, double>()));
    BOOST_CHECK(!(msg2.match_elements<atom_value, double>()));
    BOOST_CHECK(!(msg1.match_elements<atom_value, int, int>()));
    BOOST_CHECK(!(msg2.match_elements<atom_value, int, int>()));
}

BOOST_AUTO_TEST_SUITE_END()
