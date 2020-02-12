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

#pragma once

#include <nil/actor/detail/type_list.hpp>
#include <nil/actor/detail/type_traits.hpp>
#include <nil/actor/sum_type_access.hpp>
#include <nil/actor/sum_type_token.hpp>

namespace nil {
    namespace actor {

        /// Concept for checking whether `T` supports the sum type API by specializing
        /// `sum_type_access`.
        template<class T>
        constexpr bool SumType() {
            return has_sum_type_access<typename std::decay<T>::type>::value;
        }

        /// Concept for checking whether all `Ts` support the sum type API by
        /// specializing `sum_type_access`.
        template<class... Ts>
        constexpr bool SumTypes() {
            using namespace detail;
            using types = type_list<decay_t<Ts>...>;
            return tl_forall<types, has_sum_type_access>::value;
        }

        template<class Trait, class T, bool = Trait::specialized>
        struct sum_type_index {
            static constexpr int value = -1;
        };

        template<class Trait, class T>
        struct sum_type_index<Trait, T, true> {
            static constexpr int value = detail::tl_index_of<typename Trait::types, T>::value;
        };

        template<class Trait, class T>
        constexpr sum_type_token<T, sum_type_index<Trait, T>::value> make_sum_type_token() {
            return {};
        }

        /// Returns a reference to the value of a sum type.
        /// @pre `holds_alternative<T>(x)`
        /// @relates SumType
        template<class T, class U, class Trait = sum_type_access<U>>
        auto get(U &x) -> decltype(Trait::get(x, make_sum_type_token<Trait, T>())) {
            return Trait::get(x, make_sum_type_token<Trait, T>());
        }

        /// Returns a reference to the value of a sum type.
        /// @pre `holds_alternative<T>(x)`
        /// @relates SumType
        template<class T, class U, class Trait = sum_type_access<U>>
        auto get(const U &x) -> decltype(Trait::get(x, make_sum_type_token<Trait, T>())) {
            return Trait::get(x, make_sum_type_token<Trait, T>());
        }

        /// Returns a pointer to the value of a sum type if it is of type `T`,
        /// `nullptr` otherwise.
        /// @relates SumType
        template<class T, class U, class Trait = sum_type_access<U>>
        auto get_if(U *x) -> decltype(Trait::get_if(x, make_sum_type_token<Trait, T>())) {
            return Trait::get_if(x, make_sum_type_token<Trait, T>());
        }

        /// Returns a pointer to the value of a sum type if it is of type `T`,
        /// `nullptr` otherwise.
        /// @relates SumType
        template<class T, class U, class Trait = sum_type_access<U>>
        auto get_if(const U *x) -> decltype(Trait::get_if(x, make_sum_type_token<Trait, T>())) {
            return Trait::get_if(x, make_sum_type_token<Trait, T>());
        }

        /// Returns whether a sum type has a value of type `T`.
        /// @relates SumType
        template<class T, class U>
        bool holds_alternative(const U &x) {
            using namespace detail;
            using trait = sum_type_access<U>;
            return trait::is(x, make_sum_type_token<trait, T>());
        }

        template<bool Valid, class F, class... Ts>
        struct sum_type_visit_result_impl {
            using type = decltype((std::declval<F &>())(std::declval<typename sum_type_access<Ts>::type0 &>()...));
        };

        template<class F, class... Ts>
        struct sum_type_visit_result_impl<false, F, Ts...> {};

        template<class F, class... Ts>
        struct sum_type_visit_result
            : sum_type_visit_result_impl<detail::conjunction<SumType<Ts>()...>::value, F, Ts...> {};

        template<class F, class... Ts>
        using sum_type_visit_result_t =
            typename sum_type_visit_result<detail::decay_t<F>, detail::decay_t<Ts>...>::type;

        template<class Result, size_t I, class Visitor>
        struct visit_impl_continuation;

        template<class Result, size_t I>
        struct visit_impl {
            template<class Visitor, class T, class... Ts>
            static Result apply(Visitor &&f, T &&x, Ts &&... xs) {
                visit_impl_continuation<Result, I - 1, Visitor> continuation {f};
                using trait = sum_type_access<detail::decay_t<T>>;
                return trait::template apply<Result>(x, continuation, std::forward<Ts>(xs)...);
            }
        };

        template<class Result>
        struct visit_impl<Result, 0> {
            template<class Visitor, class... Ts>
            static Result apply(Visitor &&f, Ts &&... xs) {
                return f(std::forward<Ts>(xs)...);
            }
        };

        template<class Result, size_t I, class Visitor>
        struct visit_impl_continuation {
            Visitor &f;
            template<class... Ts>
            Result operator()(Ts &&... xs) {
                return visit_impl<Result, I>::apply(f, std::forward<Ts>(xs)...);
            }
        };

        /// Applies the values of any number of sum types to the visitor.
        /// @relates SumType
        template<class Visitor, class T, class... Ts, class Result = sum_type_visit_result_t<Visitor, T, Ts...>>
        typename std::enable_if<SumTypes<T, Ts...>(), Result>::type visit(Visitor &&f, T &&x, Ts &&... xs) {
            return visit_impl<Result, sizeof...(Ts) + 1>::apply(std::forward<Visitor>(f), std::forward<T>(x),
                                                                std::forward<Ts>(xs)...);
        }

    }    // namespace actor
}    // namespace nil
