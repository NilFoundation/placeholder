//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE inspector

#include <nil/actor/test/dsl.hpp>

#include <list>
#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <nil/actor/spawner.hpp>
#include <nil/actor/spawner_config.hpp>
#include <nil/actor/binary_deserializer.hpp>
#include <nil/actor/binary_serializer.hpp>
#include <nil/actor/byte_buffer.hpp>
#include <nil/actor/detail/meta_object.hpp>
#include <nil/actor/detail/stringification_inspector.hpp>

using namespace nil::actor;

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<template<typename...> class P, typename... T>
            struct print_log_value<P<T...>> {
                void operator()(std::ostream &, P<T...> const &) {
                }
            };

            template<template<typename, std::size_t> class P, typename T, std::size_t S>
            struct print_log_value<P<T, S>> {
                void operator()(std::ostream &, P<T, S> const &) {
                }
            };
            template<>
            struct print_log_value<dummy_struct> {
                void operator()(std::ostream &, dummy_struct const &) {
                }
            };
            template<>
            struct print_log_value<dummy_enum_class> {
                void operator()(std::ostream &, dummy_enum_class const &) {
                }
            };
            template<>
            struct print_log_value<dummy_tag_type> {
                void operator()(std::ostream &, dummy_tag_type const &) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

namespace {

    template<class T>
    class inspector_adapter_base {
    public:
        inspector_adapter_base(T &impl) : impl_(impl) {
            // nop
        }

    protected:
        T &impl_;
    };

    template<class RoundtripPolicy>
    struct check_impl {
        RoundtripPolicy &p_;

        template<class T>
        bool operator()(T x) {
            return p_(x);
        }
    };

    template<class T>
    using nl = std::numeric_limits<T>;

    template<class Policy>
    void test_impl(Policy &p) {
        check_impl<Policy> check {p};
        // check primitive types
        BOOST_CHECK(check(true));
        BOOST_CHECK(check(false));
        BOOST_CHECK(check(nl<int8_t>::lowest()));
        BOOST_CHECK(check(nl<int8_t>::max()));
        BOOST_CHECK(check(nl<uint8_t>::lowest()));
        BOOST_CHECK(check(nl<uint8_t>::max()));
        BOOST_CHECK(check(nl<int16_t>::lowest()));
        BOOST_CHECK(check(nl<int16_t>::max()));
        BOOST_CHECK(check(nl<uint16_t>::lowest()));
        BOOST_CHECK(check(nl<uint16_t>::max()));
        BOOST_CHECK(check(nl<int32_t>::lowest()));
        BOOST_CHECK(check(nl<int32_t>::max()));
        BOOST_CHECK(check(nl<uint32_t>::lowest()));
        BOOST_CHECK(check(nl<uint32_t>::max()));
        BOOST_CHECK(check(nl<int64_t>::lowest()));
        BOOST_CHECK(check(nl<int64_t>::max()));
        BOOST_CHECK(check(nl<uint64_t>::lowest()));
        BOOST_CHECK(check(nl<uint64_t>::max()));
        BOOST_CHECK(check(nl<float>::lowest()));
        BOOST_CHECK(check(nl<float>::max()));
        BOOST_CHECK(check(nl<double>::lowest()));
        BOOST_CHECK(check(nl<double>::max()));
        BOOST_CHECK(check(nl<long double>::lowest()));
        BOOST_CHECK(check(nl<long double>::max()));
        // various containers
        BOOST_CHECK(check(std::array<int, 3> {{1, 2, 3}}));
        BOOST_CHECK(check(std::vector<char> {}));
        BOOST_CHECK(check(std::vector<char> {1, 2, 3}));
        BOOST_CHECK(check(std::vector<int> {}));
        BOOST_CHECK(check(std::vector<int> {1, 2, 3}));
        BOOST_CHECK(check(std::list<int> {}));
        BOOST_CHECK(check(std::list<int> {1, 2, 3}));
        BOOST_CHECK(check(std::set<int> {}));
        BOOST_CHECK(check(std::set<int> {1, 2, 3}));
        BOOST_CHECK(check(std::unordered_set<int> {}));
        BOOST_CHECK(check(std::unordered_set<int> {1, 2, 3}));
        BOOST_CHECK(check(std::map<int, int> {}));
        BOOST_CHECK(check(std::map<int, int> {{1, 1}, {2, 2}, {3, 3}}));
        BOOST_CHECK(check(std::unordered_map<int, int> {}));
        BOOST_CHECK(check(std::unordered_map<int, int> {{1, 1}, {2, 2}, {3, 3}}));
        // user-defined types
        BOOST_CHECK(check(dummy_struct {10, "hello"}));
        // optionals
        BOOST_CHECK(check(optional<int> {}));
        BOOST_CHECK(check(optional<int> {42}));
        // strings
        BOOST_CHECK(check(std::string {}));
        BOOST_CHECK(check(std::string {""}));
        BOOST_CHECK(check(std::string {"test"}));
        BOOST_CHECK(check(std::u16string {}));
        BOOST_CHECK(check(std::u16string {u""}));
        BOOST_CHECK(check(std::u16string {u"test"}));
        BOOST_CHECK(check(std::u32string {}));
        BOOST_CHECK(check(std::u32string {U""}));
        BOOST_CHECK(check(std::u32string {U"test"}));
        // enums
        BOOST_CHECK(check(de_foo));
        BOOST_CHECK(check(de_bar));
        BOOST_CHECK(check(dummy_enum_class::foo));
        BOOST_CHECK(check(dummy_enum_class::bar));
        // empty type
        BOOST_CHECK(check(dummy_tag_type {}));
        // pair and tuple
        BOOST_CHECK(check(std::make_pair(std::string("hello"), 42)));
        BOOST_CHECK(check(std::make_pair(std::make_pair(1, 2), 3)));
        BOOST_CHECK(check(std::make_pair(std::make_tuple(1, 2), 3)));
        BOOST_CHECK(check(std::make_tuple(1, 2, 3, 4)));
        BOOST_CHECK(check(std::make_tuple(std::make_tuple(1, 2, 3), 4)));
        BOOST_CHECK(check(std::make_tuple(std::make_pair(1, 2), 3, 4)));
        // variant<>
        BOOST_CHECK(check(variant<none_t> {}));
        BOOST_CHECK(check(variant<none_t, int, std::string> {}));
        BOOST_CHECK(check(variant<none_t, int, std::string> {42}));
        BOOST_CHECK(check(variant<none_t, int, std::string> {std::string {"foo"}}));
    }

    struct stringification_inspector_policy {
        template<class T>
        std::string f(T &x) {
            std::string str;
            detail::stringification_inspector fun {str};
            fun(x);
            return str;
        }

        // only check for compilation for complex types
        template<class T>
        typename std::enable_if<!std::is_integral<T>::value, bool>::type operator()(T &x) {
            BOOST_TEST_MESSAGE("f(x) = " << f(x));
            return true;
        }

        // check result for integral types
        template<class T>
        typename std::enable_if<std::is_integral<T>::value, bool>::type operator()(T &x) {
            BOOST_CHECK_EQUAL(f(x), std::to_string(x));
            return true;
        }

        // check result for bool
        bool operator()(bool &x) {
            BOOST_CHECK_EQUAL(f(x), std::string {x ? "true" : "false"});
            return true;
        }
    };

}    // namespace

BOOST_AUTO_TEST_CASE(stringification_inspector) {
    stringification_inspector_policy p;
    test_impl(p);
}

namespace {

    template<class T>
    struct is_integral_or_enum {
        static constexpr bool value = std::is_integral<T>::value || std::is_enum<T>::value;
    };

    struct binary_serialization_policy {
        execution_unit &context;

        template<class T>
        auto to_buf(const T &x) {
            byte_buffer result;
            binary_serializer sink {&context, result};
            if (auto err = sink(x))
                BOOST_FAIL("failed to serialize");
            return result;
        }

        template<class T>
        detail::enable_if_t<is_integral_or_enum<T>::value, bool> operator()(T &x) {
            auto buf = to_buf(x);
            binary_deserializer source {&context, buf};
            auto y = static_cast<T>(0);
            if (auto err = source(y))
                BOOST_FAIL("failed to deserialize from buffer");
            BOOST_CHECK_EQUAL(x, y);
            return detail::safe_equal(x, y);
        }

        template<class T>
        detail::enable_if_t<!is_integral_or_enum<T>::value, bool> operator()(T &x) {
            auto buf = to_buf(x);
            binary_deserializer source {&context, buf};
            T y;
            if (auto err = source(y))
                BOOST_FAIL("failed to deserialize from buffer");
            BOOST_CHECK_EQUAL(x, y);
            return detail::safe_equal(x, y);
        }
    };

}    // namespace

BOOST_AUTO_TEST_CASE(binary_serialization_inspectors) {
    spawner_config cfg;
    spawner sys {cfg};
    scoped_execution_unit context;
    binary_serialization_policy p {context};
    test_impl(p);
}
