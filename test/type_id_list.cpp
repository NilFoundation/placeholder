//---------------------------------------------------------------------------//
// Copyright (c) 2011-2020 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE type_id_list

#include <nil/actor/type_id_list.hpp>

#include <nil/actor/test/dsl.hpp>

using namespace nil::actor;

BOOST_AUTO_TEST_CASE(lists_store_the_size_at_index_0) {
    type_id_t data[] = {3, 1, 2, 4};
    type_id_list xs {data};
    BOOST_CHECK_EQUAL(xs.size(), 3u);
    BOOST_CHECK_EQUAL(xs[0], 1u);
    BOOST_CHECK_EQUAL(xs[1], 2u);
    BOOST_CHECK_EQUAL(xs[2], 4u);
}

BOOST_AUTO_TEST_CASE(lists_are_comparable) {
    type_id_t data[] = {3, 1, 2, 4};
    type_id_list xs {data};
    type_id_t data_copy[] = {3, 1, 2, 4};
    type_id_list ys {data_copy};
    BOOST_CHECK_EQUAL(xs, ys);
    data_copy[1] = 10;
    BOOST_CHECK_NE(xs, ys);
    BOOST_CHECK_LT(xs, ys);
    BOOST_CHECK_EQUAL(make_type_id_list<add_atom>(), make_type_id_list<add_atom>());
    BOOST_CHECK_NE(make_type_id_list<add_atom>(), make_type_id_list<ok_atom>());
}

BOOST_AUTO_TEST_CASE(make_type_id_list_constructs_a_list_from_types) {
    auto xs = make_type_id_list<uint8_t, bool, float>();
    BOOST_CHECK_EQUAL(xs.size(), 3u);
    BOOST_CHECK_EQUAL(xs[0], type_id_v<uint8_t>);
    BOOST_CHECK_EQUAL(xs[1], type_id_v<bool>);
    BOOST_CHECK_EQUAL(xs[2], type_id_v<float>);
}

BOOST_AUTO_TEST_CASE(type_id_lists_are_convertible_to_strings) {
    nil::actor::init_global_meta_objects<nil::actor::id_block::core_test>();
    nil::actor::init_global_meta_objects<nil::actor::id_block::core_module>();

    auto xs = make_type_id_list<uint16_t, bool, float>();
    BOOST_CHECK_EQUAL(to_string(xs), "[uint16_t, bool, float]");
}
