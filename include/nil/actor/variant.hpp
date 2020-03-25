//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt for Boost License or
// http://opensource.org/licenses/BSD-3-Clause for BSD 3-Clause License
//---------------------------------------------------------------------------//

#pragma once

#include <functional>
#include <memory>
#include <type_traits>

#include <nil/actor/config.hpp>
#include <nil/actor/default_sum_type_access.hpp>
#include <nil/actor/fwd.hpp>
#include <nil/actor/raise_error.hpp>
#include <nil/actor/static_visitor.hpp>
#include <nil/actor/sum_type.hpp>
#include <nil/actor/sum_type_access.hpp>

#include <nil/actor/meta/omittable.hpp>

#include <nil/actor/detail/type_list.hpp>
#include <nil/actor/detail/type_traits.hpp>
#include <nil/actor/detail/variant_data.hpp>

#define ACTOR_VARIANT_CASE(n) \
    case n:                 \
        return f(std::forward<Us>(xs)..., x.get(std::integral_constant<int, (n <= max_type_id ? n : 0)>()))

#define ACTOR_VARIANT_ASSIGN_CASE(n)                                                                         \
    case n: {                                                                                              \
        using tmp_t = typename detail::tl_at<detail::type_list<Ts...>, (n < sizeof...(Ts) ? n : 0)>::type; \
        x.x = tmp_t {};                                                                                    \
        return f(get<tmp_t>(x.x));                                                                         \
    }

namespace nil {
    namespace actor {

        constexpr size_t variant_npos = static_cast<size_t>(-1);

        template<class T>
        struct is_variant : std::false_type {};

        template<class... Ts>
        struct is_variant<variant<Ts...>> : std::true_type {};

        template<class... Ts>
        struct is_variant<variant<Ts...> &> : std::true_type {};

        template<class... Ts>
        struct is_variant<const variant<Ts...> &> : std::true_type {};

        template<class... Ts>
        struct is_variant<const variant<Ts...> &&> : std::true_type {};

        template<class... Ts>
        using is_variant_t = typename is_variant<Ts...>::type;

        template<class T>
        struct variant_assign_helper {
            using result_type = void;
            T &lhs;
            variant_assign_helper(T &lhs_ref) : lhs(lhs_ref) {
            }
            template<class U>
            void operator()(const U &rhs) const {
                lhs = rhs;
            }
        };

        template<class T>
        struct variant_move_helper {
            using result_type = void;
            T &lhs;
            variant_move_helper(T &lhs_ref) : lhs(lhs_ref) {
            }
            template<class U>
            void operator()(U &rhs) const {
                lhs = std::move(rhs);
            }
        };

        template<bool Valid, class F, class... Ts>
        struct variant_visit_result_impl {
            using type = decltype((std::declval<F &>())(std::declval<typename Ts::type0 &>()...));
        };

        template<class F, class... Ts>
        struct variant_visit_result_impl<false, F, Ts...> {};

        template<class F, class... Ts>
        struct variant_visit_result
            : variant_visit_result_impl<detail::conjunction<is_variant<Ts>::value...>::value, F, Ts...> {};

        template<class F, class... Ts>
        using variant_visit_result_t = typename variant_visit_result<detail::decay_t<F>, detail::decay_t<Ts>...>::type;

        /// A variant represents always a valid value of one of the types `Ts...`.
        template<class... Ts>
        class variant {
        public:
            // -- member types -----------------------------------------------------------

            using types = detail::type_list<Ts...>;

            using type0 = typename detail::tl_at<types, 0>::type;

            // -- constants --------------------------------------------------------------

            /// Stores the ID for the last type.
            static constexpr int max_type_id = sizeof...(Ts) - 1;

            /// Stores whether all types are nothrow constructible.
            static constexpr bool nothrow_move_construct =
                detail::conjunction<std::is_nothrow_move_constructible<Ts>::value...>::value;

            /// Stores whether all types are nothrow assignable *and* constructible. We
            /// need to check both, since assigning to a variant results in a
            /// move-contruct unless the before and after types are the same.
            static constexpr bool nothrow_move_assign =
                nothrow_move_construct && detail::conjunction<std::is_nothrow_move_assignable<Ts>::value...>::value;

            // -- sanity checks ----------------------------------------------------------

            static_assert(sizeof...(Ts) <= 20, "Too many template arguments given.");

            static_assert(sizeof...(Ts) > 0, "No template argument given.");

            static_assert(!detail::tl_exists<types, std::is_reference>::value, "Cannot create a variant of references");

            // -- constructors, destructors, and assignment operators --------------------

            variant() : type_(variant_npos) {
                // Never empty ...
                set(typename detail::tl_head<types>::type());
                // ... unless an exception was thrown above.
                type_ = 0;
            }

            template<class U>
            variant(U &&arg) noexcept(std::is_rvalue_reference<U &&>::value &&nothrow_move_assign) :
                type_(variant_npos) {
                set(std::forward<U>(arg));
            }

            variant(variant &&other) noexcept(nothrow_move_construct) : type_(variant_npos) {
                variant_move_helper<variant> helper {*this};
                other.template apply<void>(helper);
            }

            variant(const variant &other) : type_(variant_npos) {
                variant_assign_helper<variant> helper {*this};
                other.template apply<void>(helper);
            }

            variant &operator=(const variant &other) {
                variant_assign_helper<variant> helper {*this};
                other.template apply<void>(helper);
                return *this;
            }

            variant &operator=(variant &&other) noexcept(nothrow_move_assign) {
                variant_move_helper<variant> helper {*this};
                other.template apply<void>(helper);
                return *this;
            }

            template<class U>
            variant &operator=(U &&arg) noexcept(nothrow_move_assign) {
                set(std::forward<U>(arg));
                return *this;
            }

            ~variant() {
                destroy_data();
            }

            // -- properties -------------------------------------------------------------

            constexpr size_t index() const {
                return static_cast<size_t>(type_);
            }

            bool valueless_by_exception() const {
                return index() == variant_npos;
            }

            /// @cond PRIVATE

            inline variant &get_data() {
                return *this;
            }

            inline const variant &get_data() const {
                return *this;
            }

            template<int Pos>
            bool is(std::integral_constant<int, Pos>) const {
                return type_ == static_cast<size_t>(Pos);
            }

            template<class T>
            bool is() const {
                using namespace detail;
                int_token<tl_index_where<type_list<Ts...>, tbind<is_same_ish, T>::template type>::value> token;
                return is(token);
            }

            template<int Pos>
            const typename detail::tl_at<types, Pos>::type &get(std::integral_constant<int, Pos> token) const {
                return data_.get(token);
            }

            template<int Pos>
            typename detail::tl_at<types, Pos>::type &get(std::integral_constant<int, Pos> token) {
                return data_.get(token);
            }

            template<class Result, class Visitor, class... Variants>
            Result apply(Visitor &&visitor, Variants &&... xs) const {
                return apply_impl<Result>(*this, std::forward<Visitor>(visitor), std::forward<Variants>(xs)...);
            }

            template<class Result, class Visitor, class... Variants>
            Result apply(Visitor &&visitor, Variants &&... xs) {
                return apply_impl<Result>(*this, std::forward<Visitor>(visitor), std::forward<Variants>(xs)...);
            }

            template<class Result, class Self, class Visitor, class... Us>
            static Result apply_impl(Self &x, Visitor &&f, Us &&... xs) {
                switch (x.type_) {
                    default:
                        ACTOR_RAISE_ERROR("invalid type found");
                        ACTOR_VARIANT_CASE(0);
                        ACTOR_VARIANT_CASE(1);
                        ACTOR_VARIANT_CASE(2);
                        ACTOR_VARIANT_CASE(3);
                        ACTOR_VARIANT_CASE(4);
                        ACTOR_VARIANT_CASE(5);
                        ACTOR_VARIANT_CASE(6);
                        ACTOR_VARIANT_CASE(7);
                        ACTOR_VARIANT_CASE(8);
                        ACTOR_VARIANT_CASE(9);
                        ACTOR_VARIANT_CASE(10);
                        ACTOR_VARIANT_CASE(11);
                        ACTOR_VARIANT_CASE(12);
                        ACTOR_VARIANT_CASE(13);
                        ACTOR_VARIANT_CASE(14);
                        ACTOR_VARIANT_CASE(15);
                        ACTOR_VARIANT_CASE(16);
                        ACTOR_VARIANT_CASE(17);
                        ACTOR_VARIANT_CASE(18);
                        ACTOR_VARIANT_CASE(19);
                }
            }

            /// @endcond

        private:
            inline void destroy_data() {
                if (type_ == variant_npos)
                    return;    // nothing to do
                detail::variant_data_destructor f;
                apply<void>(f);
            }

            template<class U>
            void set(U &&arg) {
                using namespace detail;
                using type = typename std::decay<U>::type;
                static constexpr int type_id =
                    detail::tl_index_where<types, detail::tbind<is_same_ish, type>::template type>::value;
                static_assert(type_id >= 0, "invalid type for variant");
                std::integral_constant<int, type_id> token;
                if (type_ != type_id) {
                    destroy_data();
                    type_ = type_id;
                    auto &ref = data_.get(token);
                    new (std::addressof(ref)) type(std::forward<U>(arg));
                } else {
                    data_.get(token) = std::forward<U>(arg);
                }
            }

            template<class... Us>
            void set(const variant<Us...> &other) {
                using namespace detail;
                static_assert(tl_subset_of<type_list<Us...>, types>::value,
                              "cannot set variant of type A to variant of type B "
                              "unless the element types of A are a strict subset of "
                              "the element types of B");
                variant_assign_helper<variant> helper {*this};
                other.template apply<void>(helper);
            }

            template<class... Us>
            void set(variant<Us...> &other) {
                set(const_cast<const variant<Us...> &>(other));
            }

            template<class... Us>
            void set(variant<Us...> &&other) {
                using namespace detail;
                static_assert(tl_subset_of<type_list<Us...>, types>::value,
                              "cannot set variant of type A to variant of type B "
                              "unless the element types of A are a strict subset of "
                              "the element types of B");
                variant_move_helper<variant> helper {*this};
                other.template apply<void>(helper);
            }

            size_t type_;
            detail::variant_data<typename lift_void<Ts>::type...> data_;
        };

        /// Enable `holds_alternative`, `get`, `get_if`, and `visit` for `variant`.
        /// @relates variant
        /// @relates SumType
        template<class... Ts>
        struct sum_type_access<variant<Ts...>> : default_sum_type_access<variant<Ts...>> {
            // nop
        };

        /// @relates variant
        template<template<class> class Predicate>
        struct variant_compare_helper {
            template<class T>
            bool operator()(const T &x, const T &y) const {
                Predicate<T> f;
                return f(x, y);
            }

            template<class T, class U>
            bool operator()(const T &, const U &) const {
                return false;
            }
        };

        /// @relates variant
        template<class... Ts>
        bool operator==(const variant<Ts...> &x, const variant<Ts...> &y) {
            variant_compare_helper<std::equal_to> f;
            return x.index() == y.index() && visit(f, x, y);
        }

        /// @relates variant
        template<class... Ts>
        bool operator!=(const variant<Ts...> &x, const variant<Ts...> &y) {
            return !(x == y);
        }

        /// @relates variant
        template<class... Ts>
        bool operator<(const variant<Ts...> &x, const variant<Ts...> &y) {
            if (y.valueless_by_exception())
                return false;
            if (x.valueless_by_exception())
                return true;
            if (x.index() != y.index())
                return x.index() < y.index();
            variant_compare_helper<std::less> f;
            return visit(f, x, y);
        }

        /// @relates variant
        template<class... Ts>
        bool operator>(const variant<Ts...> &x, const variant<Ts...> &y) {
            if (x.valueless_by_exception())
                return false;
            if (y.valueless_by_exception())
                return true;
            if (x.index() != y.index())
                return x.index() > y.index();
            variant_compare_helper<std::greater> f;
            return visit(f, x, y);
        }

        /// @relates variant
        template<class... Ts>
        bool operator<=(const variant<Ts...> &x, const variant<Ts...> &y) {
            return !(x > y);
        }

        /// @relates variant
        template<class... Ts>
        bool operator>=(const variant<Ts...> &x, const variant<Ts...> &y) {
            return !(x < y);
        }

        /// @relates variant
        template<class T>
        struct variant_reader {
            uint8_t &type_tag;
            T &x;
        };

        /// @relates variant
        template<class Inspector, class... Ts>
        typename Inspector::result_type inspect(Inspector &f, variant_reader<variant<Ts...>> &x) {
            return x.x.template apply<typename Inspector::result_type>(f);
        }

        /// @relates variant
        template<class Inspector, class... Ts>
        typename std::enable_if<Inspector::reads_state, typename Inspector::result_type>::type
            inspect(Inspector &f, variant<Ts...> &x) {
            // We use a single byte for the type index on the wire.
            auto type_tag = static_cast<uint8_t>(x.index());
            variant_reader<variant<Ts...>> helper {type_tag, x};
            return f(meta::omittable(), type_tag, helper);
        }

        /// @relates variant
        template<class T>
        struct variant_writer {
            uint8_t &type_tag;
            T &x;
        };

        /// @relates variant
        template<class Inspector, class... Ts>
        typename Inspector::result_type inspect(Inspector &f, variant_writer<variant<Ts...>> &x) {
            switch (x.type_tag) {
                default:
                    ACTOR_RAISE_ERROR("invalid type found");
                    ACTOR_VARIANT_ASSIGN_CASE(0);
                    ACTOR_VARIANT_ASSIGN_CASE(1);
                    ACTOR_VARIANT_ASSIGN_CASE(2);
                    ACTOR_VARIANT_ASSIGN_CASE(3);
                    ACTOR_VARIANT_ASSIGN_CASE(4);
                    ACTOR_VARIANT_ASSIGN_CASE(5);
                    ACTOR_VARIANT_ASSIGN_CASE(6);
                    ACTOR_VARIANT_ASSIGN_CASE(7);
                    ACTOR_VARIANT_ASSIGN_CASE(8);
                    ACTOR_VARIANT_ASSIGN_CASE(9);
                    ACTOR_VARIANT_ASSIGN_CASE(10);
                    ACTOR_VARIANT_ASSIGN_CASE(11);
                    ACTOR_VARIANT_ASSIGN_CASE(12);
                    ACTOR_VARIANT_ASSIGN_CASE(13);
                    ACTOR_VARIANT_ASSIGN_CASE(14);
                    ACTOR_VARIANT_ASSIGN_CASE(15);
                    ACTOR_VARIANT_ASSIGN_CASE(16);
                    ACTOR_VARIANT_ASSIGN_CASE(17);
                    ACTOR_VARIANT_ASSIGN_CASE(18);
                    ACTOR_VARIANT_ASSIGN_CASE(19);
            }
        }

        /// @relates variant
        template<class Inspector, class... Ts>
        typename std::enable_if<Inspector::writes_state, typename Inspector::result_type>::type
            inspect(Inspector &f, variant<Ts...> &x) {
            // We use a single byte for the type index on the wire.
            uint8_t type_tag;
            variant_writer<variant<Ts...>> helper {type_tag, x};
            return f(meta::omittable(), type_tag, helper);
        }

    }    // namespace actor
}    // namespace nil
