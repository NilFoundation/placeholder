//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt or
// http://opensource.org/licenses/BSD-3-Clause
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE atom_test

#include <boost/test/unit_test.hpp>

#include <string>

#include <nil/actor/all.hpp>
#include <nil/actor/config.hpp>

using namespace nil::actor;

namespace {

    constexpr auto s_foo = atom("FooBar");

    using a_atom = atom_constant<atom("a")>;
    using b_atom = atom_constant<atom("b")>;
    using c_atom = atom_constant<atom("c")>;
    using abc_atom = atom_constant<atom("abc")>;
    using def_atom = atom_constant<atom("def")>;
    using foo_atom = atom_constant<atom("foo")>;

    struct fixture {
        fixture() : system(cfg) {
            // nop
        }

        spawner_config cfg;
        spawner system;
    };

}    // namespace

BOOST_FIXTURE_TEST_SUITE(atom_tests, fixture)

BOOST_AUTO_TEST_CASE(basics_test) {
    // check if there are leading bits that distinguish "zzz" and "000 "
    BOOST_CHECK(atom("zzz") != atom("000 "));
    // check if there are leading bits that distinguish "abc" and " abc"
    BOOST_CHECK(atom("abc") != atom(" abc"));
    // 'illegal' characters are mapped to whitespaces
    BOOST_CHECK(atom("   ") == atom("@!?"));
    // check to_string impl
    BOOST_CHECK_EQUAL(to_string(s_foo), "FooBar");
}

struct send_to_self {
    explicit send_to_self(blocking_actor *self) : self_(self) {
        // nop
    }

    template<class... Ts>
    void operator()(Ts &&... xs) {
        self_->send(self_, std::forward<Ts>(xs)...);
    }

    blocking_actor *self_;
};

BOOST_AUTO_TEST_CASE(receive_atoms_test) {
    scoped_actor self {system};
    send_to_self f {self.ptr()};
    f(foo_atom::value, static_cast<uint32_t>(42));
    f(abc_atom::value, def_atom::value, "cstring");
    f(1.f);
    f(a_atom::value, b_atom::value, c_atom::value, 23.f);
    bool matched_pattern[3] = {false, false, false};
    int i = 0;
    BOOST_TEST_MESSAGE("start receive loop");
    for (i = 0; i < 3; ++i) {
        self->receive(
            [&](foo_atom, uint32_t value) {
                matched_pattern[0] = true;
                BOOST_CHECK_EQUAL(value, 42u);
            },
            [&](abc_atom, def_atom, const std::string &str) {
                matched_pattern[1] = true;
                BOOST_CHECK_EQUAL(str, "cstring");
            },
            [&](a_atom, b_atom, c_atom, float value) {
                matched_pattern[2] = true;
                BOOST_CHECK_EQUAL(value, 23.f);
            });
    }
    BOOST_CHECK(matched_pattern[0] && matched_pattern[1] && matched_pattern[2]);
    self->receive([](float) {
        // erase float message
    });
    atom_value x = atom("abc");
    atom_value y = abc_atom::value;
    BOOST_CHECK(x == y);
    auto msg = make_message(atom("abc"));
    self->send(self, msg);
    self->receive([](abc_atom) { BOOST_TEST_MESSAGE("received 'abc'"); });
}

using testee = typed_actor<replies_to<abc_atom>::with<int>>;

testee::behavior_type testee_impl(testee::pointer self) {
    return {[=](abc_atom) {
        self->quit();
        return 42;
    }};
}

BOOST_AUTO_TEST_CASE(request_atom_constants_test) {
    scoped_actor self {system};
    auto tst = system.spawn(testee_impl);
    self->request(tst, infinite, abc_atom::value)
        .receive([](int i) { BOOST_CHECK_EQUAL(i, 42); },
                 [&](error &err) { BOOST_FAIL("err: " << system.render(err)); });
}

BOOST_AUTO_TEST_CASE(runtime_conversion_test) {
    BOOST_CHECK(atom("foo") == atom_from_string("foo"));
    BOOST_CHECK(atom("") == atom_from_string("tooManyCharacters"));
}

BOOST_AUTO_TEST_SUITE_END()
