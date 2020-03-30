//---------------------------------------------------------------------------//
// Copyright (c) 2011-2019 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE detail.parse

#include <nil/actor/detail/parse.hpp>

#include <nil/actor/test/dsl.hpp>

#include <nil/actor/expected.hpp>
#include <nil/actor/ipv4_address.hpp>
#include <nil/actor/ipv4_endpoint.hpp>
#include <nil/actor/ipv4_subnet.hpp>
#include <nil/actor/ipv6_address.hpp>
#include <nil/actor/ipv6_endpoint.hpp>
#include <nil/actor/ipv6_subnet.hpp>
#include <nil/actor/string_view.hpp>
#include <nil/actor/uri.hpp>

using namespace nil::actor;

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<>
            struct print_log_value<nil::actor::ipv4_address> {
                void operator()(std::ostream &, nil::actor::ipv4_address const &) {
                }
            };
            template<>
            struct print_log_value<nil::actor::ipv4_endpoint> {
                void operator()(std::ostream &, nil::actor::ipv4_endpoint const &) {
                }
            };
            template<>
            struct print_log_value<nil::actor::ipv4_subnet> {
                void operator()(std::ostream &, nil::actor::ipv4_subnet const &) {
                }
            };
            template<>
            struct print_log_value<nil::actor::ipv6_address> {
                void operator()(std::ostream &, nil::actor::ipv6_address const &) {
                }
            };
            template<>
            struct print_log_value<nil::actor::ipv6_endpoint> {
                void operator()(std::ostream &, nil::actor::ipv6_endpoint const &) {
                }
            };
            template<>
            struct print_log_value<nil::actor::ipv6_subnet> {
                void operator()(std::ostream &, nil::actor::ipv6_subnet const &) {
                }
            };
            template<template<typename...> class T, typename... P>
            struct print_log_value<T<P...>> {
                void operator()(std::ostream &, T<P...> const &) {
                }
            };
            template<>
            struct print_log_value<nil::actor::pec> {
                void operator()(std::ostream &, nil::actor::pec const &) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

namespace {

    using std::chrono::duration_cast;

    timespan operator"" _ns(unsigned long long x) {
        return duration_cast<timespan>(std::chrono::nanoseconds(x));
    }

    timespan operator"" _us(unsigned long long x) {
        return duration_cast<timespan>(std::chrono::microseconds(x));
    }

    timespan operator"" _ms(unsigned long long x) {
        return duration_cast<timespan>(std::chrono::milliseconds(x));
    }

    timespan operator"" _s(unsigned long long x) {
        return duration_cast<timespan>(std::chrono::seconds(x));
    }

    timespan operator"" _h(unsigned long long x) {
        return duration_cast<timespan>(std::chrono::hours(x));
    }

    template<class T>
    expected<T> read(string_view str) {
        T result;
        string_parser_state ps {str.begin(), str.end()};
        detail::parse(ps, result);
        if (ps.code == pec::success)
            return result;
        return make_error(ps);
    }

}    // namespace

#define CHECK_NUMBER(type, value) BOOST_CHECK_EQUAL(read<type>(#value), type(value))

#define CHECK_NUMBER_3(type, value, cpp_value) BOOST_CHECK_EQUAL(read<type>(#value), type(cpp_value))

#define CHECK_INVALID(type, str, code) BOOST_CHECK_EQUAL(read<type>(str), code)

BOOST_AUTO_TEST_CASE(valid_signed_integers) {
    CHECK_NUMBER(int8_t, -128);
    CHECK_NUMBER(int8_t, 127);
    CHECK_NUMBER(int8_t, +127);
    CHECK_NUMBER(int16_t, -32768);
    CHECK_NUMBER(int16_t, 32767);
    CHECK_NUMBER(int16_t, +32767);
    CHECK_NUMBER(int32_t, -2147483648);
    CHECK_NUMBER(int32_t, 2147483647);
    CHECK_NUMBER(int32_t, +2147483647);
    CHECK_NUMBER(int64_t, -9223372036854775807);
    CHECK_NUMBER(int64_t, 9223372036854775807);
    CHECK_NUMBER(int64_t, +9223372036854775807);
}

BOOST_AUTO_TEST_CASE(invalid_signed_integers) {
    CHECK_INVALID(int8_t, "--1", pec::unexpected_character);
    CHECK_INVALID(int8_t, "++1", pec::unexpected_character);
    CHECK_INVALID(int8_t, "-129", pec::integer_underflow);
    CHECK_INVALID(int8_t, "128", pec::integer_overflow);
    CHECK_INVALID(int8_t, "~1", pec::unexpected_character);
    CHECK_INVALID(int8_t, "1!", pec::trailing_character);
    CHECK_INVALID(int8_t, "+", pec::unexpected_eof);
    CHECK_INVALID(int8_t, "-", pec::unexpected_eof);
}

BOOST_AUTO_TEST_CASE(valid_unsigned_integers) {
    CHECK_NUMBER(uint8_t, 0);
    CHECK_NUMBER(uint8_t, +0);
    CHECK_NUMBER(uint8_t, 255);
    CHECK_NUMBER(uint8_t, +255);
    CHECK_NUMBER(uint16_t, 0);
    CHECK_NUMBER(uint16_t, +0);
    CHECK_NUMBER(uint16_t, 65535);
    CHECK_NUMBER(uint16_t, +65535);
    CHECK_NUMBER(uint32_t, 0);
    CHECK_NUMBER(uint32_t, +0);
    CHECK_NUMBER(uint32_t, 4294967295);
    CHECK_NUMBER(uint32_t, +4294967295);
    CHECK_NUMBER(uint64_t, 0);
    CHECK_NUMBER(uint64_t, +0);
    CHECK_NUMBER_3(uint64_t, 18446744073709551615, 18446744073709551615ULL);
    CHECK_NUMBER_3(uint64_t, +18446744073709551615, 18446744073709551615ULL);
}

BOOST_AUTO_TEST_CASE(invalid_unsigned_integers) {
    CHECK_INVALID(uint8_t, "-1", pec::unexpected_character);
    CHECK_INVALID(uint8_t, "++1", pec::unexpected_character);
    CHECK_INVALID(uint8_t, "256", pec::integer_overflow);
    CHECK_INVALID(uint8_t, "~1", pec::unexpected_character);
    CHECK_INVALID(uint8_t, "1!", pec::trailing_character);
    CHECK_INVALID(uint8_t, "+", pec::unexpected_eof);
}

BOOST_AUTO_TEST_CASE(valid_floating_point_numbers) {
    CHECK_NUMBER(float, 1);
    CHECK_NUMBER(double, 1);
    CHECK_NUMBER(double, 0.01e10);
    CHECK_NUMBER(double, 10e-10);
    CHECK_NUMBER(double, -10e-10);
}

BOOST_AUTO_TEST_CASE(invalid_floating_point_numbers) {
    CHECK_INVALID(float, "1..", pec::trailing_character);
    CHECK_INVALID(double, "..1", pec::unexpected_character);
    CHECK_INVALID(double, "+", pec::unexpected_eof);
    CHECK_INVALID(double, "-", pec::unexpected_eof);
    CHECK_INVALID(double, "1e", pec::unexpected_eof);
    CHECK_INVALID(double, "--0.01e10", pec::unexpected_character);
    CHECK_INVALID(double, "++10e-10", pec::unexpected_character);
}

BOOST_AUTO_TEST_CASE(valid_timespans) {
    BOOST_CHECK_EQUAL(read<timespan>("12ns"), 12_ns);
    BOOST_CHECK_EQUAL(read<timespan>("34us"), 34_us);
    BOOST_CHECK_EQUAL(read<timespan>("56ms"), 56_ms);
    BOOST_CHECK_EQUAL(read<timespan>("78s"), 78_s);
    BOOST_CHECK_EQUAL(read<timespan>("60min"), 1_h);
    BOOST_CHECK_EQUAL(read<timespan>("90h"), 90_h);
}

BOOST_AUTO_TEST_CASE(invalid_timespans) {
    BOOST_CHECK_EQUAL(read<timespan>("12"), pec::unexpected_eof);
    BOOST_CHECK_EQUAL(read<timespan>("12nas"), pec::unexpected_character);
    BOOST_CHECK_EQUAL(read<timespan>("34usec"), pec::trailing_character);
    BOOST_CHECK_EQUAL(read<timespan>("56m"), pec::unexpected_eof);
}

BOOST_AUTO_TEST_CASE(strings) {
    BOOST_CHECK_EQUAL(read<std::string>("    foo\t  "), "foo");
    BOOST_CHECK_EQUAL(read<std::string>("  \"  foo\t\"  "), "  foo\t");
}

BOOST_AUTO_TEST_CASE(lists) {
    using int_list = std::vector<int>;
    using string_list = std::vector<std::string>;
    BOOST_CHECK_EQUAL(read<int_list>("1"), int_list({1}));
    BOOST_CHECK_EQUAL(read<int_list>("1, 2, 3"), int_list({1, 2, 3}));
    BOOST_CHECK_EQUAL(read<int_list>("[1, 2, 3]"), int_list({1, 2, 3}));
    BOOST_CHECK_EQUAL(read<string_list>("a, b , \" c \""), string_list({"a", "b", " c "}));
}

BOOST_AUTO_TEST_CASE(maps) {
    using int_map = std::map<std::string, int>;
    BOOST_CHECK_EQUAL(read<int_map>(R"(a=1, "b" = 42)"), int_map({{"a", 1}, {"b", 42}}));
    BOOST_CHECK_EQUAL(read<int_map>(R"({   a  = 1  , b   =    42   ,} )"), int_map({{"a", 1}, {"b", 42}}));
}

BOOST_AUTO_TEST_CASE(uris) {
    using uri_list = std::vector<uri>;
    auto x_res = read<uri>("foo:bar");
    if (x_res == none) {
        BOOST_ERROR("my:path not recognized as URI");
        return;
    }
    auto x = *x_res;
    BOOST_CHECK_EQUAL(x.scheme(), "foo");
    BOOST_CHECK_EQUAL(x.path(), "bar");
    auto ls = unbox(read<uri_list>("foo:bar, <http://actor-framework.org/doc>"));
    BOOST_REQUIRE_EQUAL(ls.size(), 2u);
    BOOST_CHECK_EQUAL(ls[0].scheme(), "foo");
    BOOST_CHECK_EQUAL(ls[0].path(), "bar");
    BOOST_CHECK_EQUAL(ls[1].scheme(), "http");
    //    BOOST_CHECK_EQUAL(ls[1].authority().host, std::string {"actor-framework.org"});
    BOOST_CHECK_EQUAL(ls[1].path(), "doc");
}

BOOST_AUTO_TEST_CASE(IPv4_address_test) {
    BOOST_CHECK_EQUAL(read<ipv4_address>("1.2.3.4"), ipv4_address({1, 2, 3, 4}));
    BOOST_CHECK_EQUAL(read<ipv4_address>("127.0.0.1"), ipv4_address({127, 0, 0, 1}));
    BOOST_CHECK_EQUAL(read<ipv4_address>("256.0.0.1"), pec::integer_overflow);
}

BOOST_AUTO_TEST_CASE(IPv4_subnet_test) {
    BOOST_CHECK_EQUAL(read<ipv4_subnet>("1.2.3.0/24"), ipv4_subnet(ipv4_address({1, 2, 3, 0}), 24));
    BOOST_CHECK_EQUAL(read<ipv4_subnet>("1.2.3.0/33"), pec::integer_overflow);
}

BOOST_AUTO_TEST_CASE(IPv4_endpoint_test) {
    BOOST_CHECK_EQUAL(read<ipv4_endpoint>("127.0.0.1:0"), ipv4_endpoint(ipv4_address({127, 0, 0, 1}), 0));
    BOOST_CHECK_EQUAL(read<ipv4_endpoint>("127.0.0.1:65535"), ipv4_endpoint(ipv4_address({127, 0, 0, 1}), 65535));
    BOOST_CHECK_EQUAL(read<ipv4_endpoint>("127.0.0.1:65536"), pec::integer_overflow);
}

BOOST_AUTO_TEST_CASE(IPv6_address_test) {
    BOOST_CHECK_EQUAL(read<ipv6_address>("1.2.3.4"), ipv4_address({1, 2, 3, 4}));
    BOOST_CHECK_EQUAL(read<ipv6_address>("1::"), ipv6_address({{1}, {}}));
    BOOST_CHECK_EQUAL(read<ipv6_address>("::2"), ipv6_address({{}, {2}}));
    BOOST_CHECK_EQUAL(read<ipv6_address>("1::2"), ipv6_address({{1}, {2}}));
}

BOOST_AUTO_TEST_CASE(IPv6_subnet_test) {
    BOOST_CHECK_EQUAL(read<ipv6_subnet>("1.2.3.0/24"), ipv6_subnet(ipv4_address({1, 2, 3, 0}), 24));
    BOOST_CHECK_EQUAL(read<ipv6_subnet>("1::/128"), ipv6_subnet(ipv6_address({1}, {}), 128));
    BOOST_CHECK_EQUAL(read<ipv6_subnet>("1::/129"), pec::integer_overflow);
}

BOOST_AUTO_TEST_CASE(IPv6_endpoint_test) {
    BOOST_CHECK_EQUAL(read<ipv6_endpoint>("127.0.0.1:0"), ipv6_endpoint(ipv4_address({127, 0, 0, 1}), 0));
    BOOST_CHECK_EQUAL(read<ipv6_endpoint>("127.0.0.1:65535"), ipv6_endpoint(ipv4_address({127, 0, 0, 1}), 65535));
    BOOST_CHECK_EQUAL(read<ipv6_endpoint>("127.0.0.1:65536"), pec::integer_overflow);
    BOOST_CHECK_EQUAL(read<ipv6_endpoint>("[1::2]:8080"), ipv6_endpoint({{1}, {2}}, 8080));
}
