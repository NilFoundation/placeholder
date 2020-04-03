//---------------------------------------------------------------------------//
// Copyright (c) 2011-2019 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE detail.serialized_size

#include <nil/actor/detail/serialized_size.hpp>

#include <nil/actor/test/dsl.hpp>

#include <vector>

#include <nil/actor/binary_serializer.hpp>
#include <nil/actor/byte.hpp>
#include <nil/actor/byte_buffer.hpp>

using namespace nil::actor;

using nil::actor::detail::serialized_size;

namespace {

    struct fixture : test_coordinator_fixture<> {
        template<class... Ts>
        size_t actual_size(const Ts &... xs) {
            byte_buffer buf;
            binary_serializer sink {sys, buf};
            if (auto err = sink(xs...))
                BOOST_FAIL("failed to serialize data: " << sys.render(err));
            return buf.size();
        }
    };

}    // namespace

#define CHECK_SAME_SIZE(value) BOOST_CHECK_EQUAL(serialized_size(value), actual_size(value))

BOOST_FIXTURE_TEST_SUITE(serialized_size_tests, fixture)

BOOST_AUTO_TEST_CASE(numbers) {
    CHECK_SAME_SIZE(int8_t {42});
    CHECK_SAME_SIZE(int16_t {42});
    CHECK_SAME_SIZE(int32_t {42});
    CHECK_SAME_SIZE(int64_t {42});
    CHECK_SAME_SIZE(uint8_t {42});
    CHECK_SAME_SIZE(uint16_t {42});
    CHECK_SAME_SIZE(uint32_t {42});
    CHECK_SAME_SIZE(uint64_t {42});
    CHECK_SAME_SIZE(4.2f);
    CHECK_SAME_SIZE(4.2);
}

BOOST_AUTO_TEST_CASE(containers) {
    CHECK_SAME_SIZE(std::string {"foobar"});
    CHECK_SAME_SIZE(std::vector<char>({'a', 'b', 'c'}));
    CHECK_SAME_SIZE(std::vector<std::string>({"hello", "world"}));
}

BOOST_AUTO_TEST_CASE(messages) {
    CHECK_SAME_SIZE(make_message(42));
    CHECK_SAME_SIZE(make_message(1, 2, 3));
    CHECK_SAME_SIZE(make_message("hello", "world"));
}

BOOST_AUTO_TEST_SUITE_END()
