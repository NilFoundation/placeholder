//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2024 Martun Karapetyan <martun@nil.foundation>
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE big_uint_randomized_test

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <optional>
#include <ostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include <boost/json/src.hpp>
#include <boost/lexical_cast.hpp>

#include "nil/crypto3/multiprecision/big_uint.hpp"
#include "nil/crypto3/multiprecision/detail/int128.hpp"

using namespace nil::crypto3::multiprecision;

decltype(auto) test_cases(const std::string &test_name) {
    static boost::json::object test_dataset;
    static bool initialized = false;
    if (!initialized) {
        std::ifstream file(std::string(TEST_DATA_DIR) +
                           "/big_uint_randomized_test_cases.json");
        test_dataset = boost::json::parse(file).get_object();
        initialized = true;
    }

    return test_dataset.at(test_name).as_array();
}

enum class integer_kind {
    big_uint,
    unsigned_builtin,
    signed_builtin,
};

template<std::size_t Bits>
struct type_with_bits {
    using unsigned_type = void;
    using signed_type = void;
};

template<>
struct type_with_bits<8> {
    using unsigned_type = std::uint8_t;
    using signed_type = std::int8_t;
};

template<>
struct type_with_bits<16> {
    using unsigned_type = std::uint16_t;
    using signed_type = std::int16_t;
};

template<>
struct type_with_bits<32> {
    using unsigned_type = std::uint32_t;
    using signed_type = std::int32_t;
};

template<>
struct type_with_bits<64> {
    using unsigned_type = std::uint64_t;
    using signed_type = std::int64_t;
};

#ifdef NIL_CO3_MP_HAS_INT128
template<>
struct type_with_bits<128> {
    using unsigned_type = nil::crypto3::multiprecision::detail::uint128_t;
    using signed_type = nil::crypto3::multiprecision::detail::int128_t;
};
#endif

template<std::size_t Bits>
using unsigned_type_with_bits_t = typename type_with_bits<Bits>::unsigned_type;

template<std::size_t Bits>
using signed_type_with_bits_t = typename type_with_bits<Bits>::signed_type;

template<std::size_t Bits, integer_kind Kind>
using integer_type = std::conditional_t<
    Kind == integer_kind::big_uint, big_uint<Bits>,
    std::conditional_t<Kind == integer_kind::unsigned_builtin,
                       unsigned_type_with_bits_t<Bits>, signed_type_with_bits_t<Bits>>>;

template<std::size_t Bits1, integer_kind Kind1, std::size_t Bits2, integer_kind Kind2>
struct ArithmeticSample {
    static_assert(Kind1 == integer_kind::big_uint || Kind2 == integer_kind::big_uint);

    using T1 = integer_type<Bits1, Kind1>;
    using T2 = integer_type<Bits2, Kind2>;
    static constexpr std::size_t ResBits =
        std::max(Kind1 == integer_kind::big_uint ? Bits1 : 0,
                 Kind2 == integer_kind::big_uint ? Bits2 : 0);
    static constexpr integer_kind ResKind = integer_kind::big_uint;
    using R = big_uint<ResBits>;

    static_assert(!std::is_void_v<T1>, "Unsupported Bits1 for builtin integers");
    static_assert(!std::is_void_v<T2>, "Unsupported Bits2 for builtin integers");

    template<std::size_t Bits, integer_kind Kind = integer_kind::big_uint>
    integer_type<Bits, Kind> parse(const std::string_view s) {
        if constexpr (Kind == integer_kind::big_uint) {
            return big_uint<Bits>(s);
        } else if constexpr (Bits == 8 && (Kind == integer_kind::unsigned_builtin ||
                                           Kind == integer_kind::signed_builtin)) {
            // lexical_cast does not work with char
            return boost::numeric_cast<integer_type<Bits, Kind>>(
                boost::lexical_cast<int>(s));
        } else {
            return boost::lexical_cast<integer_type<Bits, Kind>>(s);
        }
    }

    template<std::size_t Bits, integer_kind Kind = integer_kind::big_uint>
    std::optional<integer_type<Bits, Kind>> parse_or_empty(std::string_view s) {
        if (s.empty()) {
            return std::nullopt;
        }
        return parse<Bits, Kind>(s);
    }

    ArithmeticSample(const boost::json::object &sample) : json(sample) {
        // NOLINTBEGIN
        a = parse<Bits1, Kind1>(sample.at("a").as_string());
        b = parse<Bits2, Kind2>(sample.at("b").as_string());

        a_add_b = parse_or_empty<ResBits, ResKind>(sample.at("a_add_b").as_string());
        a_sub_b = parse_or_empty<ResBits, ResKind>(sample.at("a_sub_b").as_string());
        a_mul_b = parse_or_empty<ResBits, ResKind>(sample.at("a_mul_b").as_string());
        a_div_b = parse_or_empty<ResBits, ResKind>(sample.at("a_div_b").as_string());
        a_mod_b = parse_or_empty<ResBits, ResKind>(sample.at("a_mod_b").as_string());

        a_wrapping_add_b = sample.at("a_wrapping_add_b").as_string();
        a_wrapping_sub_b = sample.at("a_wrapping_sub_b").as_string();
        a_wrapping_mul_b = sample.at("a_wrapping_mul_b").as_string();

        a_or_b = parse_or_empty<ResBits, ResKind>(sample.at("a_or_b").as_string());
        a_and_b = parse_or_empty<ResBits, ResKind>(sample.at("a_and_b").as_string());
        a_xor_b = parse_or_empty<ResBits, ResKind>(sample.at("a_xor_b").as_string());

        cmp_a_b = sample.at("cmp_a_b").as_int64();
        // NOLINTEND
    }

    friend std::ostream &operator<<(std::ostream &os, const ArithmeticSample &sample) {
        os << sample.json;
        return os;
    }

    T1 a;
    T2 b;
    std::optional<R> a_add_b;
    std::optional<R> a_sub_b;
    std::optional<R> a_mul_b;
    std::optional<R> a_div_b;
    std::optional<R> a_mod_b;
    R a_wrapping_add_b;
    R a_wrapping_sub_b;
    R a_wrapping_mul_b;
    std::optional<R> a_or_b;
    std::optional<R> a_and_b;
    std::optional<R> a_xor_b;
    int cmp_a_b;

    // NOLINTNEXTLINE
    const boost::json::object &json;
};

template<std::size_t Bits1, integer_kind Kind1, std::size_t Bits2, integer_kind Kind2>
void base_operations_test(const ArithmeticSample<Bits1, Kind1, Bits2, Kind2> sample) {
    const auto &a = sample.a;
    const auto &b = sample.b;
    const auto &cmp_a_b = sample.cmp_a_b;

    if (sample.a_add_b) {
        BOOST_CHECK_EQUAL(a + b, *sample.a_add_b);
    } else {
        BOOST_CHECK_THROW(a + b, std::overflow_error);
    }

    if (sample.a_sub_b) {
        BOOST_CHECK_EQUAL(a - b, *sample.a_sub_b);
    } else {
        if (a >= 0) {
            BOOST_CHECK_THROW(a - b, std::overflow_error);
        } else {
            BOOST_CHECK_THROW(a - b, std::range_error);
        }
    }

    if (sample.a_mul_b) {
        BOOST_CHECK_EQUAL(a * b, *sample.a_mul_b);
    } else {
        if (a >= 0 && b >= 0) {
            BOOST_CHECK_THROW(a * b, std::overflow_error);
        } else {
            BOOST_CHECK_THROW(a * b, std::range_error);
        }
    }

    if (sample.a_div_b) {
        BOOST_CHECK_EQUAL(a / b, *sample.a_div_b);
    } else {
        if (a >= 0 && b >= 0) {
            BOOST_CHECK_THROW(a / b, std::overflow_error);
        } else {
            BOOST_CHECK_THROW(a / b, std::range_error);
        }
    }

    if (sample.a_mod_b) {
        BOOST_CHECK_EQUAL(a % b, *sample.a_mod_b);
    } else {
        if (a >= 0 && b >= 0) {
            BOOST_CHECK_THROW(a % b, std::overflow_error);
        } else {
            BOOST_CHECK_THROW(a % b, std::range_error);
        }
    }

    BOOST_CHECK_EQUAL(wrapping_add(a, b), sample.a_wrapping_add_b);
    BOOST_CHECK_EQUAL(wrapping_sub(a, b), sample.a_wrapping_sub_b);
    BOOST_CHECK_EQUAL(wrapping_mul(a, b), sample.a_wrapping_mul_b);

    if (sample.a_or_b) {
        BOOST_CHECK_EQUAL(a | b, *sample.a_or_b);
    } else {
        if (a >= 0 && b >= 0) {
            BOOST_CHECK_THROW(a | b, std::overflow_error);
        } else {
            BOOST_CHECK_THROW(a | b, std::range_error);
        }
    }

    if (sample.a_and_b) {
        BOOST_CHECK_EQUAL(a & b, *sample.a_and_b);
    } else {
        BOOST_CHECK_THROW(a & b, std::range_error);
    }

    if (sample.a_xor_b) {
        BOOST_CHECK_EQUAL(a ^ b, *sample.a_xor_b);
    } else {
        if (a >= 0 && b >= 0) {
            BOOST_CHECK_THROW(a ^ b, std::overflow_error);
        } else {
            BOOST_CHECK_THROW(a ^ b, std::range_error);
        }
    }

    BOOST_CHECK_EQUAL(a > b, cmp_a_b > 0);
    BOOST_CHECK_EQUAL(a >= b, cmp_a_b >= 0);
    BOOST_CHECK_EQUAL(a == b, cmp_a_b == 0);
    BOOST_CHECK_EQUAL(a < b, cmp_a_b < 0);
    BOOST_CHECK_EQUAL(a <= b, cmp_a_b <= 0);
    BOOST_CHECK_EQUAL(a != b, cmp_a_b != 0);
}

BOOST_AUTO_TEST_SUITE(base_operations)

#define BASE_OPERATIONS_TEST(BITS1, KIND1, BITS2, KIND2)                              \
    BOOST_DATA_TEST_CASE(                                                             \
        base_operations_##BITS1##_##KIND1##_##BITS2##_##KIND2,                        \
        (test_cases("base_operations_" #BITS1 "_" #KIND1 "_" #BITS2 "_" #KIND2))) {   \
        base_operations_test(                                                         \
            ArithmeticSample<BITS1, integer_kind::KIND1, BITS2, integer_kind::KIND2>( \
                sample.as_object()));                                                 \
    }

#include "generated_test_data/big_uint_randomized_test_instances.hpp"

BOOST_AUTO_TEST_SUITE_END()
