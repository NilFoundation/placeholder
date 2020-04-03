//---------------------------------------------------------------------------//
// Copyright (c) 2011-2019 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE detail.parser.read_unsigned_integer

#include <nil/actor/detail/parser/read_unsigned_integer.hpp>

#include <nil/actor/test/dsl.hpp>

#include <nil/actor/parser_state.hpp>
#include <nil/actor/string_view.hpp>
#include <nil/actor/variant.hpp>

using namespace nil::actor;

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<template<typename...> class P, typename... T>
            struct print_log_value<P<T...>> {
                void operator()(std::ostream &, P<T...> const &) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

namespace {

    template<class T>
    struct unsigned_integer_consumer {
        using value_type = T;

        void value(T y) {
            x = y;
        }

        T x;
    };

    template<class T>
    optional<T> read(string_view str) {
        unsigned_integer_consumer<T> consumer;
        string_parser_state ps {str.begin(), str.end()};
        detail::parser::read_unsigned_integer(ps, consumer);
        if (ps.code != pec::success)
            return none;
        return consumer.x;
    }

    template<class T>
    bool overflow(string_view str) {
        unsigned_integer_consumer<T> consumer;
        string_parser_state ps {str.begin(), str.end()};
        detail::parser::read_unsigned_integer(ps, consumer);
        return ps.code == pec::integer_overflow;
    }

    template<class T>
    T max_val() {
        return std::numeric_limits<T>::max();
    }

}    // namespace

#define ZERO_VALUE(type, literal) BOOST_CHECK_EQUAL(read<type>(#literal), type(0));

#define MAX_VALUE(type, literal) BOOST_CHECK_EQUAL(read<type>(#literal), max_val<type>());

#ifdef OVERFLOW
#undef OVERFLOW
#endif    // OVERFLOW

#define OVERFLOW(type, literal) BOOST_CHECK(overflow<type>(#literal));

BOOST_AUTO_TEST_CASE(read_zeros) {
    ZERO_VALUE(uint8_t, 0);
    ZERO_VALUE(uint8_t, 00);
    ZERO_VALUE(uint8_t, 0x0);
    ZERO_VALUE(uint8_t, 0X00);
    ZERO_VALUE(uint8_t, 0b0);
    ZERO_VALUE(uint8_t, 0B00);
    ZERO_VALUE(uint8_t, +0);
    ZERO_VALUE(uint8_t, +00);
    ZERO_VALUE(uint8_t, +0x0);
    ZERO_VALUE(uint8_t, +0X00);
    ZERO_VALUE(uint8_t, +0b0);
    ZERO_VALUE(uint8_t, +0B00);
}

BOOST_AUTO_TEST_CASE(maximal_value) {
    MAX_VALUE(uint8_t, 0b11111111);
    MAX_VALUE(uint8_t, 0377);
    MAX_VALUE(uint8_t, 255);
    MAX_VALUE(uint8_t, 0xFF);
    OVERFLOW(uint8_t, 0b100000000);
    OVERFLOW(uint8_t, 0400);
    OVERFLOW(uint8_t, 256);
    OVERFLOW(uint8_t, 0x100);
    MAX_VALUE(uint16_t, 0b1111111111111111);
    MAX_VALUE(uint16_t, 0177777);
    MAX_VALUE(uint16_t, 65535);
    MAX_VALUE(uint16_t, 0xFFFF);
    OVERFLOW(uint16_t, 0b10000000000000000);
    OVERFLOW(uint16_t, 0200000);
    OVERFLOW(uint16_t, 65536);
    OVERFLOW(uint16_t, 0x10000);
    MAX_VALUE(uint32_t, 0b11111111111111111111111111111111);
    MAX_VALUE(uint32_t, 037777777777);
    MAX_VALUE(uint32_t, 4294967295);
    MAX_VALUE(uint32_t, 0xFFFFFFFF);
    OVERFLOW(uint32_t, 0b100000000000000000000000000000000);
    OVERFLOW(uint32_t, 040000000000);
    OVERFLOW(uint32_t, 4294967296);
    OVERFLOW(uint32_t, 0x100000000);
    MAX_VALUE(uint64_t, 0b1111111111111111111111111111111111111111111111111111111111111111);
    MAX_VALUE(uint64_t, 01777777777777777777777);
    MAX_VALUE(uint64_t, 18446744073709551615);
    MAX_VALUE(uint64_t, 0xFFFFFFFFFFFFFFFF);
    OVERFLOW(uint64_t, 0b10000000000000000000000000000000000000000000000000000000000000000);
    OVERFLOW(uint64_t, 02000000000000000000000);
    OVERFLOW(uint64_t, 18446744073709551616);
    OVERFLOW(uint64_t, 0x10000000000000000);
}
