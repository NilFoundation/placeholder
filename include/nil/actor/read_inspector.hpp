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

#include <type_traits>

#include <nil/actor/detail/squashed_int.hpp>
#include <nil/actor/detail/type_traits.hpp>
#include <nil/actor/detail/inspect.hpp>

#include <nil/actor/meta/annotation.hpp>
#include <nil/actor/meta/save_callback.hpp>

#include <nil/actor/allowed_unsafe_message_type.hpp>
#include <nil/actor/unifyn.hpp>
#include <nil/actor/sec.hpp>

#define ACTOR_READ_INSPECTOR_TRY(statement)                                           \
    using ACTOR_UNIFYN(statement_result) = decltype(statement);                       \
    if constexpr (std::is_same<ACTOR_UNIFYN(statement_result), void>::value) {        \
        statement;                                                                  \
    } else if constexpr (std::is_same<ACTOR_UNIFYN(statement_result), bool>::value) { \
        if (!statement)                                                             \
            return false;                                                           \
    } else if (auto err = statement) {                                              \
        result = err;                                                               \
        return false;                                                               \
    }

namespace nil {
    namespace actor {

        template<typename Subtype>
        class read_inspector {
        public:
            static constexpr bool reads_state = true;

            static constexpr bool writes_state = false;

            template<class... Ts>
            [[nodiscard]] auto operator()(Ts &&... xs) {
                typename Subtype::result_type result;
                static_cast<void>((try_apply(result, xs) && ...));
                return result;
            }

        private:
            template<class Tuple, size_t... Is>
            static auto apply_tuple(Subtype &dref, const Tuple &xs, std::index_sequence<Is...>) {
                return dref(std::get<Is>(xs)...);
            }

            template<class T, size_t... Is>
            static auto apply_array(Subtype &dref, const T *xs, std::index_sequence<Is...>) {
                return dref(xs[Is]...);
            }

            template<class R, class T>
            typename std::enable_if<meta::is_annotation_v<T>, bool>::type try_apply(R &result, T &x) {
                if constexpr (meta::is_save_callback_v<T>) {
                    ACTOR_READ_INSPECTOR_TRY(x.fun());
                }
                return true;
            }

            template<class R, class T>
            typename std::enable_if<!meta::is_annotation_v<T>, bool>::type try_apply(R &result, const T &x) {
                Subtype &dref = *static_cast<Subtype *>(this);
                if constexpr (std::is_empty<T>::value || is_allowed_unsafe_message_type_v<T>) {
                    // skip element
                } else if constexpr (std::is_integral<T>::value) {
                    using squashed_type = detail::squashed_int_t<T>;
                    auto squashed_x = static_cast<squashed_type>(x);
                    ACTOR_READ_INSPECTOR_TRY(dref.apply(squashed_x));
                } else if constexpr (detail::can_apply<Subtype, decltype(x)>::value) {
                    ACTOR_READ_INSPECTOR_TRY(dref.apply(x));
                } else if constexpr (std::is_array<T>::value) {
                    std::make_index_sequence<std::extent<T>::value> seq;
                    ACTOR_READ_INSPECTOR_TRY(apply_array(dref, x, seq));
                } else if constexpr (detail::is_stl_tuple_type<T>::value) {
                    std::make_index_sequence<std::tuple_size<T>::value> seq;
                    ACTOR_READ_INSPECTOR_TRY(apply_tuple(dref, x, seq));
                } else if constexpr (detail::is_map_like<T>::value) {
                    ACTOR_READ_INSPECTOR_TRY(dref.begin_sequence(x.size()));
                    for (const auto &kvp : x) {
                        ACTOR_READ_INSPECTOR_TRY(dref(kvp.first, kvp.second));
                    }
                    ACTOR_READ_INSPECTOR_TRY(dref.end_sequence());
                } else if constexpr (detail::is_list_like<T>::value) {
                    ACTOR_READ_INSPECTOR_TRY(dref.begin_sequence(x.size()));
                    for (const auto &value : x) {
                        ACTOR_READ_INSPECTOR_TRY(dref(value));
                    }
                    ACTOR_READ_INSPECTOR_TRY(dref.end_sequence());
                } else {
                    static_assert(detail::is_inspectable<Subtype, T>::value);
                    // We require that the implementation for `inspect` does not modify its
                    // arguments when passing a reading inspector.
                    using nil::actor::detail::inspect;
                    auto &mutable_x = const_cast<T &>(x);
                    ACTOR_READ_INSPECTOR_TRY(inspect(dref, mutable_x));
                }
                return true;
            }
        };
    }    // namespace actor
}    // namespace nil
