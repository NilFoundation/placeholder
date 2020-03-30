//---------------------------------------------------------------------------//
// Copyright (c) 2011-2020 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE node_id

#include <nil/actor/node_id.hpp>

#include <nil/actor/test/dsl.hpp>

using namespace nil::actor;

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<>
            struct print_log_value<error> {
                void operator()(std::ostream &, error const &) {
                }
            };
            template<>
            struct print_log_value<none_t> {
                void operator()(std::ostream &, none_t const &) {
                }
            };
            template<>
            struct print_log_value<node_id> {
                void operator()(std::ostream &, node_id const &) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

#define CHECK_PARSE_OK(str, ...)                           \
    do {                                                   \
        BOOST_CHECK(node_id::can_parse(str));              \
        node_id nid;                                       \
        BOOST_CHECK_EQUAL(parse(str, nid), none);          \
        BOOST_CHECK_EQUAL(nid, make_node_id(__VA_ARGS__)); \
    } while (false)

BOOST_AUTO_TEST_CASE(node_ids_are_convertible_from_string) {
    node_id::default_data::host_id_type hash {{
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
    }};
    auto uri_id = unbox(make_uri("ip://foo:8080"));
    CHECK_PARSE_OK("0102030405060708090A0B0C0D0E0F1011121314#1", 1, hash);
    CHECK_PARSE_OK("0102030405060708090A0B0C0D0E0F1011121314#123", 123, hash);
    CHECK_PARSE_OK("ip://foo:8080", uri_id);
}

#define CHECK_PARSE_FAIL(str) BOOST_CHECK(!node_id::can_parse(str))

BOOST_AUTO_TEST_CASE(node_ids_are_not_convertible_from_malformed_strings) {
    // not URIs
    CHECK_PARSE_FAIL("foobar");
    CHECK_PARSE_FAIL("CAF#1");
    // uint32_t overflow on the process ID
    CHECK_PARSE_FAIL("0102030405060708090A0B0C0D0E0F1011121314#42949672950");
}
