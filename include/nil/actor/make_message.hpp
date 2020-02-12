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

#include <tuple>
#include <sstream>
#include <type_traits>

#include <nil/actor/serialization/binary_deserializer.hpp>
#include <nil/actor/serialization/binary_serializer.hpp>
#include <nil/actor/serialization/deserializer.hpp>
#include <nil/actor/serialization/serializer.hpp>

#include <nil/actor/allowed_unsafe_message_type.hpp>
#include <nil/actor/byte.hpp>
#include <nil/actor/message.hpp>

#include <nil/actor/detail/inspect.hpp>
#include <nil/actor/detail/tuple_vals.hpp>
#include <nil/actor/detail/type_traits.hpp>

namespace nil {
    namespace actor {

        /// Unboxes atom constants, i.e., converts `atom_constant<V>` to `V`.
        /// @relates message
        template<class T, int IsPlaceholderRes = std::is_placeholder<T>::value>
        struct unbox_message_element {
            using type = index_mapping;
        };

        template<class T>
        struct unbox_message_element<T, 0> {
            using type = T;
        };

        template<atom_value V>
        struct unbox_message_element<atom_constant<V>, 0> {
            using type = atom_value;
        };

        template<>
        struct unbox_message_element<actor_control_block *, 0> {
            using type = strong_actor_ptr;
        };

        ///
        template<class T>
        struct is_serializable_or_whitelisted {
            static constexpr bool value =
                std::is_arithmetic<T>::value              //
                || std::is_empty<T>::value                //
                || std::is_enum<T>::value                 //
                || detail::is_stl_tuple_type<T>::value    //
                || detail::is_map_like<T>::value          //
                || detail::is_list_like<T>::value ||
                (detail::is_inspectable<binary_serializer, T>::value &&
                 detail::is_inspectable<binary_deserializer, T>::value &&
                 detail::is_inspectable<serializer, T>::value && detail::is_inspectable<deserializer, T>::value) ||
                allowed_unsafe_message_type<T>::value;
        };

        template<>
        struct is_serializable_or_whitelisted<byte> : std::true_type {};

        template<>
        struct is_serializable_or_whitelisted<std::string> : std::true_type {};

        template<>
        struct is_serializable_or_whitelisted<std::u16string> : std::true_type {};

        template<>
        struct is_serializable_or_whitelisted<std::u32string> : std::true_type {};

        /// Returns a new `message` containing the values `(x, xs...)`.
        /// @relates message
        template<class T, class... Ts>
        message make_message(T &&x, Ts &&... xs) {
            if constexpr (sizeof...(Ts) == 0 && std::is_same<message, std::decay_t<T>>::value) {
                return std::forward<T>(x);
            } else {
                using stored_types = detail::type_list<
                    typename unbox_message_element<typename detail::strip_and_convert<T>::type>::type,
                    typename unbox_message_element<typename detail::strip_and_convert<Ts>::type>::type...>;
                static_assert(detail::tl_forall<stored_types, is_serializable_or_whitelisted>::value,
                              "at least one type is not inspectable via inspect(Inspector&, T&). If "
                              "you are not sending this type over the network, you can whitelist "
                              "individual types by specializing nil::actor::allowed_unsafe_message_type<T> "
                              "or by using the macro CAF_ALLOW_UNSAFE_MESSAGE_TYPE");
                using storage = typename detail::tl_apply<stored_types, detail::tuple_vals>::type;
                auto ptr = make_counted<storage>(std::forward<T>(x), std::forward<Ts>(xs)...);
                return message {detail::message_data::cow_ptr {std::move(ptr)}};
            }
        }

        /// Returns an empty `message`.
        /// @relates message
        inline message make_message() {
            return message {};
        }

        struct message_factory {
            template<class... Ts>
            message operator()(Ts &&... xs) const {
                return make_message(std::forward<Ts>(xs)...);
            }
        };

        /// Converts the tuple `xs` to a message.
        template<class... Ts>
        message make_message_from_tuple(std::tuple<Ts...> xs) {
            message_factory f;
            return detail::apply_moved_args(f, detail::get_indices(xs), xs);
        }

    }    // namespace actor
}    // namespace nil
