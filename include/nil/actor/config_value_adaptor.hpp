//---------------------------------------------------------------------------//
// Copyright (c) 2011-2019 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#pragma once

#include <array>
#include <tuple>
#include <type_traits>

#include <nil/actor/config_value_adaptor_field.hpp>
#include <nil/actor/detail/config_value_adaptor_field_impl.hpp>

#include <nil/actor/detail/int_list.hpp>
#include <nil/actor/detail/type_traits.hpp>
#include <nil/actor/optional.hpp>
#include <nil/actor/span.hpp>
#include <nil/actor/string_view.hpp>

namespace nil {
    namespace actor {

        /// Interfaces between a user-defined type and =nil; Actor config values by going
        /// through intermediate values.
        template<class... Ts>
        class config_value_adaptor {
        public:
            using value_type = std::tuple<Ts...>;

            using indices = typename detail::il_indices<value_type>::type;

            using fields_tuple = typename detail::select_adaptor_fields<value_type, indices>::type;

            using array_type = std::array<config_value_field<value_type> *, sizeof...(Ts)>;

            template<class U,
                     class = detail::enable_if_t<!std::is_same<detail::decay_t<U>, config_value_adaptor>::value>,
                     class... Us>
            config_value_adaptor(U &&x, Us &&... xs) :
                fields_(make_fields(indices {}, std::forward<U>(x), std::forward<Us>(xs)...)) {
                init(indices {});
            }

            config_value_adaptor(config_value_adaptor &&) = default;

            span<typename array_type::value_type> fields() {
                return make_span(ptr_fields_);
            }

        private:
            // TODO: This is a workaround for GCC <= 5 because initializing fields_
            //       directly from (xs...) fails. Remove when moving on to newer
            //       compilers.
            template<long... Pos, class... Us>
            fields_tuple make_fields(detail::int_list<Pos...>, Us &&... xs) {
                return std::make_tuple(
                    detail::config_value_adaptor_field_impl<value_type, Pos>(std::forward<Us>(xs))...);
            }

            template<long... Pos>
            void init(detail::int_list<Pos...>) {
                ptr_fields_ = array_type {{&std::get<Pos>(fields_)...}};
            }

            fields_tuple fields_;

            array_type ptr_fields_;
        };

        template<class... Ts>
        config_value_adaptor<typename Ts::value_type...> make_config_value_adaptor(Ts... fields) {
            return {std::move(fields)...};
        }

    }    // namespace actor
}    // namespace nil