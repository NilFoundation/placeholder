//---------------------------------------------------------------------------//
// Copyright (c) 2011-2020 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE typed_behavior

#include <nil/actor/typed_behavior.hpp>

#include <nil/actor/test/dsl.hpp>

#include <cstdint>
#include <string>

#include <nil/actor/typed_actor.hpp>

using namespace nil::actor;

ACTOR_TEST(make_typed_behavior automatically deduces its types) {
    using handle =
        typed_actor<reacts_to<std::string>, replies_to<int32_t>::with<int32_t>, replies_to<double>::with<double>>;
    auto bhvr =
        make_typed_behavior([](const std::string &) {}, [](int32_t x) { return x; }, [](double x) { return x; });
    static_assert(std::is_same<handle::behavior_type, decltype(bhvr)>::value);
}
