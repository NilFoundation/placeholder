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

#define BOOST_TEST_MODULE type_erased_tuple_test

#include <boost/test/unit_test.hpp>

#include <nil/actor/config.hpp>
#include <nil/actor/all.hpp>
#include <nil/actor/make_type_erased_tuple_view.hpp>

using namespace std;
using namespace nil::actor;

BOOST_AUTO_TEST_CASE(get_as_tuple_test) {
    int x = 1;
    int y = 2;
    int z = 3;
    auto tup = make_type_erased_tuple_view(x, y, z);
    auto xs = tup.get_as_tuple<int, int, int>();
    BOOST_CHECK(xs == std::make_tuple(1, 2, 3));
}
