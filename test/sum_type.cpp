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

#define BOOST_TEST_MODULE sum_type_test

#include <boost/test/unit_test.hpp>

#include <new>
#include <map>
#include <string>

#include <nil/actor/deep_to_string.hpp>
#include <nil/actor/default_sum_type_access.hpp>
#include <nil/actor/config.hpp>
#include <nil/actor/raise_error.hpp>
#include <nil/actor/static_visitor.hpp>
#include <nil/actor/sum_type.hpp>
#include <nil/actor/sum_type_access.hpp>

#include <nil/actor/detail/overload.hpp>

namespace {

    struct tostring_visitor : nil::actor::static_visitor<std::string> {
        template<class T>
        inline std::string operator()(const T &value) {
            return to_string(value);
        }
    };

    class union_type {
    public:
        friend struct nil::actor::default_sum_type_access<union_type>;

        using T0 = int;
        using T1 = std::string;
        using T2 = std::map<int, int>;

        using types = nil::actor::detail::type_list<T0, T1, T2>;

        union_type() : index_(0), v0(0) {
            // nop
        }

        ~union_type() {
            destroy();
        }

        template<class T>
        union_type(T x) : union_type() {
            *this = x;
        }

        union_type &operator=(T0 value) {
            destroy();
            index_ = 0;
            v0 = value;
            return *this;
        }

        union_type &operator=(T1 value) {
            destroy();
            index_ = 1;
            new (&v1) T1(std::move(value));
            return *this;
        }

        union_type &operator=(T2 value) {
            destroy();
            index_ = 2;
            new (&v2) T2(std::move(value));
            return *this;
        }

    private:
        inline union_type &get_data() {
            return *this;
        }

        inline const union_type &get_data() const {
            return *this;
        }

        inline T0 &get(std::integral_constant<int, 0>) {
            BOOST_REQUIRE_EQUAL(index_, 0);
            return v0;
        }

        inline const T0 &get(std::integral_constant<int, 0>) const {
            BOOST_REQUIRE_EQUAL(index_, 0);
            return v0;
        }

        inline T1 &get(std::integral_constant<int, 1>) {
            BOOST_REQUIRE_EQUAL(index_, 1);
            return v1;
        }

        inline const T1 &get(std::integral_constant<int, 1>) const {
            BOOST_REQUIRE_EQUAL(index_, 1);
            return v1;
        }

        inline T2 &get(std::integral_constant<int, 2>) {
            BOOST_REQUIRE_EQUAL(index_, 2);
            return v2;
        }

        inline const T2 &get(std::integral_constant<int, 2>) const {
            BOOST_REQUIRE_EQUAL(index_, 2);
            return v2;
        }

        template<int Index>
        inline bool is(std::integral_constant<int, Index>) const {
            return index_ == Index;
        }

        template<class Result, class Visitor, class... Ts>
        inline Result apply(Visitor &&f, Ts &&... xs) const {
            switch (index_) {
                case 0:
                    return f(std::forward<Ts>(xs)..., v0);
                case 1:
                    return f(std::forward<Ts>(xs)..., v1);
                case 2:
                    return f(std::forward<Ts>(xs)..., v2);
            }
            ACTOR_RAISE_ERROR("invalid index in union_type");
        }

        void destroy() {
            if (index_ == 1) {
                v1.~T1();
            } else if (index_ == 2) {
                v2.~T2();
            }
        }

        int index_;
        union {
            T0 v0;
            T1 v1;
            T2 v2;
        };
    };
}    // namespace

namespace nil {
    namespace actor {

        template<>
        struct sum_type_access<union_type> : default_sum_type_access<union_type> {};

    }    // namespace actor
}    // namespace nil

using namespace nil::actor;

using std::string;
using map_type = std::map<int, int>;

namespace {

    struct stringify_t {
        string operator()(int x) const {
            return std::to_string(x);
        }

        string operator()(std::string x) const {
            return x;
        }

        string operator()(const map_type &x) const {
            return deep_to_string(x);
        }

        template<class T0, class T1>
        string operator()(const T0 &x0, const T1 &x1) const {
            return (*this)(x0) + ", " + (*this)(x1);
        }

        template<class T0, class T1, class T2>
        string operator()(const T0 &x0, const T1 &x1, const T2 &x2) const {
            return (*this)(x0, x1) + ", " + (*this)(x2);
        }
    };

    constexpr stringify_t stringify = stringify_t {};

    BOOST_AUTO_TEST_CASE(holds_alternative_test) {
        union_type x;
        BOOST_CHECK_EQUAL(holds_alternative<int>(x), true);
        BOOST_CHECK_EQUAL(holds_alternative<string>(x), false);
        BOOST_CHECK_EQUAL(holds_alternative<map_type>(x), false);
        x = string {"hello world"};
        BOOST_CHECK_EQUAL(holds_alternative<int>(x), false);
        BOOST_CHECK_EQUAL(holds_alternative<string>(x), true);
        BOOST_CHECK_EQUAL(holds_alternative<map_type>(x), false);
        x = map_type {{1, 1}, {2, 2}};
        BOOST_CHECK_EQUAL(holds_alternative<int>(x), false);
        BOOST_CHECK_EQUAL(holds_alternative<string>(x), false);
        BOOST_CHECK_EQUAL(holds_alternative<map_type>(x), true);
    }

    BOOST_AUTO_TEST_CASE(get_test) {
        union_type x;
        BOOST_CHECK_EQUAL(get<int>(x), 0);
        x = 42;
        BOOST_CHECK_EQUAL(get<int>(x), 42);
        x = string {"hello world"};
        BOOST_CHECK_EQUAL(get<string>(x), "hello world");
        x = map_type {{1, 1}, {2, 2}};
        BOOST_CHECK(get<map_type>(x) == map_type({{1, 1}, {2, 2}}));
    }

    BOOST_AUTO_TEST_CASE(get_if_test) {
        union_type x;
        BOOST_CHECK_EQUAL(get_if<int>(&x), &get<int>(x));
        BOOST_CHECK_EQUAL(get_if<string>(&x), nullptr);
        BOOST_CHECK(get_if<map_type>(&x) == nullptr);
        x = string {"hello world"};
        BOOST_CHECK_EQUAL(get_if<int>(&x), nullptr);
        BOOST_CHECK_EQUAL(get_if<string>(&x), &get<string>(x));
        BOOST_CHECK(get_if<map_type>(&x) == nullptr);
        x = map_type {{1, 1}, {2, 2}};
        BOOST_CHECK_EQUAL(get_if<int>(&x), nullptr);
        BOOST_CHECK_EQUAL(get_if<string>(&x), nullptr);
        BOOST_CHECK(get_if<map_type>(&x) == &get<map_type>(x));
    }

    BOOST_AUTO_TEST_CASE(unary_visit_test) {
        union_type x;
        BOOST_CHECK_EQUAL(visit(stringify, x), "0");
        x = string {"hello world"};
        BOOST_CHECK_EQUAL(visit(stringify, x), "hello world");
        x = map_type {{1, 1}, {2, 2}};
        BOOST_CHECK_EQUAL(visit(stringify, x), "{1 = 1, 2 = 2}");
    }

    BOOST_AUTO_TEST_CASE(binary_visit_test) {
        union_type x;
        union_type y;
        BOOST_CHECK_EQUAL(visit(stringify, x, y), "0, 0");
        x = 42;
        y = string {"hello world"};
        BOOST_CHECK_EQUAL(visit(stringify, x, y), "42, hello world");
    }

    BOOST_AUTO_TEST_CASE(ternary_visit_test) {
        union_type x;
        union_type y;
        union_type z;
        // BOOST_CHECK_EQUAL(visit(stringify, x, y, z), "0, 0, 0");
        x = 42;
        y = string {"foo"};
        z = map_type {{1, 1}, {2, 2}};
        BOOST_CHECK_EQUAL(visit(stringify, x, y, z), "42, foo, {1 = 1, 2 = 2}");
    }
}    // namespace
