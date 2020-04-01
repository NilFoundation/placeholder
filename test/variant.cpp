//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE variant

#include <nil/actor/variant.hpp>

#include <nil/actor/test/dsl.hpp>

#include <string>

#include <nil/actor/spawner.hpp>
#include <nil/actor/spawner_config.hpp>
#include <nil/actor/binary_deserializer.hpp>
#include <nil/actor/binary_serializer.hpp>
#include <nil/actor/byte_buffer.hpp>
#include <nil/actor/deep_to_string.hpp>
#include <nil/actor/none.hpp>

using namespace std::string_literals;

using namespace nil::actor;

// 20 integer wrappers for building a variant with 20 distint types
#define i_n(n)                                                       \
    class i##n {                                                     \
    public:                                                          \
        i##n(int y = 0) : x(y) {                                     \
        }                                                            \
        i##n(i##n &&other) : x(other.x) {                            \
            other.x = 0;                                             \
        }                                                            \
        i##n &operator=(i##n &&other) {                              \
            x = other.x;                                             \
            other.x = 0;                                             \
            return *this;                                            \
        }                                                            \
        i##n(const i##n &) = default;                                \
        i##n &operator=(const i##n &) = default;                     \
        int x;                                                       \
    };                                                               \
    bool operator==(int x, i##n y) {                                 \
        return x == y.x;                                             \
    }                                                                \
    bool operator==(i##n x, int y) {                                 \
        return y == x;                                               \
    }                                                                \
    bool operator==(i##n x, i##n y) {                                \
        return x.x == y.x;                                           \
    }                                                                \
    template<class Inspector>                                        \
    typename Inspector::result_type inspect(Inspector &f, i##n &x) { \
        return f(meta::type_name(BOOST_PP_STRINGIZE(i##n)), x.x);    \
    }

#define macro_repeat20(macro)                                                                                     \
    macro(01) macro(02) macro(03) macro(04) macro(05) macro(06) macro(07) macro(08) macro(09) macro(10) macro(11) \
        macro(12) macro(13) macro(14) macro(15) macro(16) macro(17) macro(18) macro(19) macro(20)

macro_repeat20(i_n)

    // a variant with 20 element types
    using v20 =
        variant<i01, i02, i03, i04, i05, i06, i07, i08, i09, i10, i11, i12, i13, i14, i15, i16, i17, i18, i19, i20>;

#define v20_test(n)                                                                                       \
    x3 = i##n {0x##n};                                                                                    \
    BOOST_CHECK_EQUAL(deep_to_string(x3), BOOST_PP_STRINGIZE(i##n) + "("s + std::to_string(0x##n) + ")"); \
    BOOST_CHECK_EQUAL(get<i##n>(v20 {x3}), i##n {0x##n});                                                 \
    x4 = x3;                                                                                              \
    BOOST_CHECK_EQUAL(get<i##n>(x4), i##n {0x##n});                                                       \
    BOOST_CHECK_EQUAL(get<i##n>(v20 {std::move(x3)}), i##n {0x##n});                                      \
    BOOST_CHECK_EQUAL(get<i##n>(x3), i##n {0});                                                           \
    x3 = std::move(x4);                                                                                   \
    BOOST_CHECK_EQUAL(get<i##n>(x4), i##n {0});                                                           \
    BOOST_CHECK_EQUAL(get<i##n>(x3), i##n {0x##n});                                                       \
    {                                                                                                     \
        byte_buffer buf;                                                                                  \
        binary_serializer sink {sys.dummy_execution_unit(), buf};                                         \
        if (auto err = sink(x3))                                                                          \
            BOOST_FAIL("failed to serialize data: " << sys.render(err));                                  \
        BOOST_CHECK_EQUAL(get<i##n>(x3), i##n {0x##n});                                                   \
        v20 tmp;                                                                                          \
        binary_deserializer source {sys.dummy_execution_unit(), buf};                                     \
        if (auto err = source(tmp))                                                                       \
            BOOST_FAIL("failed to deserialize data: " << sys.render(err));                                \
        BOOST_CHECK_EQUAL(get<i##n>(tmp), i##n {0x##n});                                                  \
        BOOST_CHECK_EQUAL(get<i##n>(tmp), get<i##n>(x3));                                                 \
    }

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<template<typename...> class P, typename... T>
            struct print_log_value<P<T...>> {
                void operator()(std::ostream &, P<T...> const &) {
                }
            };
            template<>
            struct print_log_value<none_t> {
                void operator()(std::ostream &, none_t const &) {
                }
            };
            template<>
            struct print_log_value<i01> {
                void operator()(std::ostream &, i01 const &) {
                }
            };
            template<>
            struct print_log_value<i02> {
                void operator()(std::ostream &, i02 const &) {
                }
            };
            template<>
            struct print_log_value<i03> {
                void operator()(std::ostream &, i03 const &) {
                }
            };
            template<>
            struct print_log_value<i04> {
                void operator()(std::ostream &, i04 const &) {
                }
            };
            template<>
            struct print_log_value<i05> {
                void operator()(std::ostream &, i05 const &) {
                }
            };
            template<>
            struct print_log_value<i06> {
                void operator()(std::ostream &, i06 const &) {
                }
            };
            template<>
            struct print_log_value<i07> {
                void operator()(std::ostream &, i07 const &) {
                }
            };
            template<>
            struct print_log_value<i08> {
                void operator()(std::ostream &, i08 const &) {
                }
            };
            template<>
            struct print_log_value<i09> {
                void operator()(std::ostream &, i09 const &) {
                }
            };
            template<>
            struct print_log_value<i10> {
                void operator()(std::ostream &, i10 const &) {
                }
            };
            template<>
            struct print_log_value<i11> {
                void operator()(std::ostream &, i11 const &) {
                }
            };
            template<>
            struct print_log_value<i12> {
                void operator()(std::ostream &, i12 const &) {
                }
            };
            template<>
            struct print_log_value<i13> {
                void operator()(std::ostream &, i13 const &) {
                }
            };
            template<>
            struct print_log_value<i14> {
                void operator()(std::ostream &, i14 const &) {
                }
            };
            template<>
            struct print_log_value<i15> {
                void operator()(std::ostream &, i15 const &) {
                }
            };
            template<>
            struct print_log_value<i16> {
                void operator()(std::ostream &, i16 const &) {
                }
            };
            template<>
            struct print_log_value<i17> {
                void operator()(std::ostream &, i17 const &) {
                }
            };
            template<>
            struct print_log_value<i18> {
                void operator()(std::ostream &, i18 const &) {
                }
            };
            template<>
            struct print_log_value<i19> {
                void operator()(std::ostream &, i19 const &) {
                }
            };
            template<>
            struct print_log_value<i20> {
                void operator()(std::ostream &, i20 const &) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

// copy construction, copy assign, move construction, move assign
// and finally serialization round-trip
BOOST_AUTO_TEST_CASE(copying_moving_roundtrips) {
    nil::actor::init_global_meta_objects<nil::actor::id_block::core_test>();
    nil::actor::init_global_meta_objects<nil::actor::id_block::core_module>();

    spawner_config cfg;
    spawner sys {cfg};
    // default construction
    variant<none_t> x1;
    BOOST_CHECK_EQUAL(get<none_t>(x1), none);
    variant<int, none_t> x2;
    BOOST_CHECK_EQUAL(get<int>(x2), 0);
    v20 x3;
    BOOST_CHECK_EQUAL(get<i01>(x3), i01 {0});
    v20 x4;
    macro_repeat20(v20_test);
}

namespace {

    struct test_visitor {
        template<class... Ts>
        std::string operator()(const Ts &... xs) {
            return deep_to_string(std::forward_as_tuple(xs...));
        }
    };

}    // namespace

BOOST_AUTO_TEST_CASE(constructors) {
    variant<int, std::string> a {42};
    variant<float, int, std::string> b {"bar"s};
    variant<int, std::string, double> c {123};
    variant<bool, uint8_t> d {uint8_t {252}};
    BOOST_CHECK_EQUAL(get<int>(a), 42);
    BOOST_CHECK_EQUAL(get<std::string>(b), "bar"s);
    BOOST_CHECK_EQUAL(get<int>(c), 123);
    BOOST_CHECK_NE(get<std::string>(c), "123"s);
    BOOST_CHECK_EQUAL(get<uint8_t>(d), uint8_t {252});
}

BOOST_AUTO_TEST_CASE(n_ary_visit) {
    variant<int, std::string> a {42};
    variant<float, int, std::string> b {"bar"s};
    variant<int, std::string, double> c {123};
    test_visitor f;
    BOOST_CHECK_EQUAL(visit(f, a), "(42)");
    BOOST_CHECK_EQUAL(visit(f, a, b), "(42, \"bar\")");
    BOOST_CHECK_EQUAL(visit(f, a, b, c), "(42, \"bar\", 123)");
}

BOOST_AUTO_TEST_CASE(get_if_test) {
    variant<int, std::string> b = "foo"s;
    BOOST_TEST_MESSAGE("test get_if directly");
    BOOST_CHECK_EQUAL(get_if<int>(&b), nullptr);
    BOOST_CHECK_NE(get_if<std::string>(&b), nullptr);
    BOOST_TEST_MESSAGE("test get_if via unit test framework");
    BOOST_CHECK_NE(get<int>(b), 42);
    BOOST_CHECK_EQUAL(get<std::string>(b), "foo"s);
}

BOOST_AUTO_TEST_CASE(less_than) {
    using variant_type = variant<char, int>;
    auto a = variant_type {'x'};
    auto b = variant_type {'y'};
    BOOST_CHECK(a < b);
    BOOST_CHECK(!(a > b));
    BOOST_CHECK(a <= b);
    BOOST_CHECK(!(a >= b));
    b = 42;
    BOOST_CHECK(a < b);
    BOOST_CHECK(!(a > b));
    BOOST_CHECK(a <= b);
    BOOST_CHECK(!(a >= b));
    a = 42;
    BOOST_CHECK(!(a < b));
    BOOST_CHECK(!(a > b));
    BOOST_CHECK(a <= b);
    BOOST_CHECK(a >= b);
    b = 'x';
}

BOOST_AUTO_TEST_CASE(equality) {
    variant<uint16_t, int> x = 42;
    variant<uint16_t, int> y = uint16_t {42};
    BOOST_CHECK_NE(x, y);
}
