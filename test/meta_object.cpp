//---------------------------------------------------------------------------//
// Copyright (c) 2011-2020 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE detail.meta_object

#include <nil/actor/detail/meta_object.hpp>

#include "core-test.hpp"

#include <tuple>
#include <type_traits>

#include <nil/actor/binary_deserializer.hpp>
#include <nil/actor/binary_serializer.hpp>
#include <nil/actor/detail/make_meta_object.hpp>
#include <nil/actor/init_global_meta_objects.hpp>

using namespace std::string_literals;

using namespace nil::actor;
using namespace nil::actor::detail;

size_t i32_wrapper::instances = 0;

size_t i64_wrapper::instances = 0;

namespace {

    struct fixture {
        fixture() {
            ACTOR_ASSERT(i32_wrapper::instances == 0);
        }
    };

}    // namespace

BOOST_FIXTURE_TEST_SUITE(meta_object_tests, fixture)

BOOST_AUTO_TEST_CASE(meta_objects_allow_construction_and_destruction_of_objects) {
    auto meta_i32_wrapper = make_meta_object<i32_wrapper>("i32_wrapper");
    std::aligned_storage_t<sizeof(i32_wrapper), alignof(i32_wrapper)> storage;
    meta_i32_wrapper.default_construct(&storage);
    BOOST_CHECK_EQUAL(i32_wrapper::instances, 1u);
    meta_i32_wrapper.destroy(&storage);
    BOOST_CHECK_EQUAL(i32_wrapper::instances, 0u);
}

BOOST_AUTO_TEST_CASE(meta_objects_allow_serialization_of_objects) {
    byte_buffer buf;
    auto meta_i32_wrapper = make_meta_object<i32_wrapper>("i32_wrapper");
    std::aligned_storage_t<sizeof(i32_wrapper), alignof(i32_wrapper)> storage;
    binary_serializer sink {nullptr, buf};
    meta_i32_wrapper.default_construct(&storage);
    BOOST_CHECK_EQUAL(i32_wrapper::instances, 1u);
    meta_i32_wrapper.save_binary(sink, &storage);
    i32_wrapper copy;
    BOOST_CHECK_EQUAL(i32_wrapper::instances, 2u);
    copy.value = 42;
    binary_deserializer source {nullptr, buf};
    meta_i32_wrapper.load_binary(source, &copy);
    BOOST_CHECK_EQUAL(copy.value, 0);
    meta_i32_wrapper.destroy(&storage);
    BOOST_CHECK_EQUAL(i32_wrapper::instances, 1u);
}

BOOST_AUTO_TEST_CASE(init_global_meta_objects takes care of creating a meta object table) {
    auto xs = global_meta_objects();
    BOOST_REQUIRE_EQUAL(xs.size(), nil::actor::id_block::core_test::end);
    BOOST_CHECK_EQUAL(type_name_by_id_v<type_id_v<i32_wrapper>>, "i32_wrapper"s);
    BOOST_CHECK_EQUAL(type_name_by_id_v<type_id_v<i64_wrapper>>, "i64_wrapper"s);
    BOOST_CHECK_EQUAL(xs[type_id_v<i32_wrapper>].type_name, "i32_wrapper"s);
    BOOST_CHECK_EQUAL(xs[type_id_v<i64_wrapper>].type_name, "i64_wrapper"s);
    BOOST_TEST_MESSAGE("calling init_global_meta_objects again is a no-op");
    init_global_meta_objects<id_block::core_test>();
    auto ys = global_meta_objects();
    auto same = [](const auto &x, const auto &y) { return x.type_name == y.type_name; };
    BOOST_CHECK(std::equal(xs.begin(), xs.end(), ys.begin(), ys.end(), same));
}

BOOST_AUTO_TEST_SUITE_END()
