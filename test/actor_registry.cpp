//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE actor_registry

#include <nil/actor/actor_registry.hpp>

#include <nil/actor/test/dsl.hpp>

#include <nil/actor/binary_deserializer.hpp>
#include <nil/actor/binary_serializer.hpp>

using namespace nil::actor;

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<>
            struct print_log_value<actor> {
                void operator()(std::ostream &, actor const &) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

namespace {

    behavior dummy() {
        return {[](int i) { return i; }};
    }

}    // namespace

BOOST_FIXTURE_TEST_SUITE(actor_registry_tests, test_coordinator_fixture<>)

BOOST_AUTO_TEST_CASE(erase) {
    // =nil; Actor registers a few actors by itself.
    auto baseline = sys.registry().named_actors().size();
    sys.registry().put("foo", sys.spawn(dummy));
    BOOST_CHECK_EQUAL(sys.registry().named_actors().size(), baseline + 1u);
    self->send(sys.registry().get<actor>("foo"), 42);
    run();
    expect((int), from(_).to(self).with(42));
    sys.registry().erase("foo");
    BOOST_CHECK_EQUAL(sys.registry().named_actors().size(), baseline);
}

BOOST_AUTO_TEST_CASE(serialization_roundtrips_go_through_the_registry) {
    auto hdl = sys.spawn(dummy);
    byte_buffer buf;
    binary_serializer sink {sys, buf};
    if (auto err = sink(hdl))
        BOOST_FAIL("serialization failed: " << sys.render(err));
    actor hdl2;
    binary_deserializer source {sys, buf};
    if (auto err = source(hdl2))
        BOOST_FAIL("serialization failed: " << sys.render(err));
    BOOST_CHECK_EQUAL(hdl, hdl2);
    anon_send_exit(hdl, exit_reason::user_shutdown);
}

BOOST_AUTO_TEST_SUITE_END()
