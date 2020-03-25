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

#define BOOST_TEST_MODULE composition_test

#include <nil/actor/test/dsl.hpp>

#include <nil/actor/all.hpp>

using namespace nil::actor;

namespace {

    behavior multiplier(int x) {
        return {[=](int y) { return x * y; }, [=](int y1, int y2) { return x * y1 * y2; }};
    }

    behavior adder(int x) {
        return {[=](int y) { return x + y; }, [=](int y1, int y2) { return x + y1 + y2; }};
    }

    behavior float_adder(float x) {
        return {[=](float y) { return x + y; }};
    }

    using fixture = test_coordinator_fixture<>;

}    // namespace

BOOST_FIXTURE_TEST_SUITE(composition_tests, fixture)

BOOST_AUTO_TEST_CASE(depth2_test) {
    auto stage1 = sys.spawn(multiplier, 4);
    auto stage2 = sys.spawn(adder, 10);
    auto testee = stage2 * stage1;
    self->send(testee, 1);
    expect((int), from(self).to(stage1).with(1));
    expect((int), from(self).to(stage2).with(4));
    expect((int), from(stage2).to(self).with(14));
}

BOOST_AUTO_TEST_CASE(depth3_test) {
    auto stage1 = sys.spawn(multiplier, 4);
    auto stage2 = sys.spawn(adder, 10);
    auto testee = stage1 * stage2 * stage1;
    self->send(testee, 1);
    expect((int), from(self).to(stage1).with(1));
    expect((int), from(self).to(stage2).with(4));
    expect((int), from(self).to(stage1).with(14));
    expect((int), from(stage1).to(self).with(56));
}

BOOST_AUTO_TEST_CASE(depth2_type_mismatch_test) {
    auto stage1 = sys.spawn(multiplier, 4);
    auto stage2 = sys.spawn(float_adder, 10);
    auto testee = stage2 * stage1;
    self->send(testee, 1);
    expect((int), from(self).to(stage1).with(1));
    expect((int), from(self).to(stage2).with(4));
    expect((error), from(stage2).to(self).with(sec::unexpected_message));
}

BOOST_AUTO_TEST_SUITE_END()
