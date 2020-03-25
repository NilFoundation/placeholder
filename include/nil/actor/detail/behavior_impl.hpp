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

#include <tuple>
#include <type_traits>

#include <nil/actor/none.hpp>
#include <nil/actor/variant.hpp>
#include <nil/actor/optional.hpp>
#include <nil/actor/match_case.hpp>
#include <nil/actor/make_counted.hpp>
#include <nil/actor/intrusive_ptr.hpp>

#include <nil/actor/atom.hpp>
#include <nil/actor/message.hpp>
#include <nil/actor/duration.hpp>
#include <nil/actor/ref_counted.hpp>
#include <nil/actor/skip.hpp>
#include <nil/actor/response_promise.hpp>
#include <nil/actor/timeout_definition.hpp>
#include <nil/actor/typed_response_promise.hpp>

#include <nil/actor/detail/int_list.hpp>
#include <nil/actor/detail/apply_args.hpp>
#include <nil/actor/detail/type_traits.hpp>
#include <nil/actor/detail/tail_argument_token.hpp>
#include <nil/actor/detail/invoke_result_visitor.hpp>

namespace nil {
    namespace actor {

        class message_handler;

    }
}    // namespace nil

namespace nil {
    namespace actor {
        namespace detail {

            class behavior_impl : public ref_counted {
            public:
                using pointer = intrusive_ptr<behavior_impl>;

                ~behavior_impl() override;

                behavior_impl(duration tout = duration {});

                virtual match_case::result invoke_empty(detail::invoke_result_visitor &f);

                virtual match_case::result invoke(detail::invoke_result_visitor &f, type_erased_tuple &xs);

                match_case::result invoke(detail::invoke_result_visitor &f, message &xs);

                optional<message> invoke(message &);

                optional<message> invoke(type_erased_tuple &);

                virtual void handle_timeout();

                inline const duration &timeout() const {
                    return timeout_;
                }

                pointer or_else(const pointer &other);

            protected:
                duration timeout_;
                match_case_info *begin_;
                match_case_info *end_;
            };

            template<class Tuple>
            void call_timeout_handler(Tuple &tup, std::true_type) {
                auto &f = std::get<std::tuple_size<Tuple>::value - 1>(tup);
                f.handler();
            }

            template<class Tuple>
            void call_timeout_handler(Tuple &, std::false_type) {
                // nop
            }

            template<class T, bool IsTimeout = is_timeout_definition<T>::value>
            struct lift_behavior {
                using type = trivial_match_case<T>;
            };

            template<class T>
            struct lift_behavior<T, true> {
                using type = T;
            };

            template<bool HasTimeout, class Tuple>
            struct with_generic_timeout;

            template<class... Ts>
            struct with_generic_timeout<false, std::tuple<Ts...>> {
                using type = std::tuple<Ts..., generic_timeout_definition>;
            };

            template<class... Ts>
            struct with_generic_timeout<true, std::tuple<Ts...>> {
                using type =
                    typename tl_apply<typename tl_replace_back<type_list<Ts...>, generic_timeout_definition>::type,
                                      std::tuple>::type;
            };

            template<class Tuple>
            class default_behavior_impl;

            template<class... Ts>
            class default_behavior_impl<std::tuple<Ts...>> : public behavior_impl {
            public:
                using tuple_type = std::tuple<Ts...>;

                using back_type = typename tl_back<type_list<Ts...>>::type;

                static constexpr bool has_timeout = is_timeout_definition<back_type>::value;

                static constexpr size_t num_cases = sizeof...(Ts) - (has_timeout ? 1 : 0);

                using cases = typename std::conditional<has_timeout, typename tl_pop_back<type_list<Ts...>>::type,
                                                        type_list<Ts...>>::type;

                default_behavior_impl(tuple_type &&tup) : cases_(std::move(tup)) {
                    init();
                }

                template<class... Us>
                default_behavior_impl(Us &&... xs) : cases_(std::forward<Us>(xs)...) {
                    init();
                }

                void handle_timeout() override {
                    std::integral_constant<bool, has_timeout> token;
                    call_timeout_handler(cases_, token);
                }

            private:
                void init() {
                    std::integral_constant<size_t, 0> first;
                    std::integral_constant<size_t, num_cases> last;
                    init(first, last);
                }

                template<size_t Last>
                void init(std::integral_constant<size_t, Last>, std::integral_constant<size_t, Last>) {
                    this->begin_ = arr_.data();
                    this->end_ = arr_.data() + arr_.size();
                    std::integral_constant<bool, has_timeout> token;
                    set_timeout(token);
                }

                template<size_t First, size_t Last>
                void init(std::integral_constant<size_t, First>, std::integral_constant<size_t, Last> last) {
                    auto &element = std::get<First>(cases_);
                    arr_[First] = match_case_info {element.type_token(), &element};
                    init(std::integral_constant<size_t, First + 1> {}, last);
                }

                void set_timeout(std::true_type) {
                    this->timeout_ = std::get<num_cases>(cases_).timeout;
                }

                void set_timeout(std::false_type) {
                    // nop
                }

                tuple_type cases_;
                std::array<match_case_info, num_cases> arr_;
            };

            template<class Tuple>
            struct behavior_factory {
                template<class... Ts>
                typename behavior_impl::pointer operator()(Ts &&... xs) const {
                    return make_counted<default_behavior_impl<Tuple>>(std::forward<Ts>(xs)...);
                }
            };

            struct make_behavior_t {
                constexpr make_behavior_t() {
                    // nop
                }

                template<class... Ts>
                intrusive_ptr<default_behavior_impl<std::tuple<typename lift_behavior<Ts>::type...>>>
                    operator()(Ts... xs) const {
                    using type = default_behavior_impl<std::tuple<typename lift_behavior<Ts>::type...>>;
                    return make_counted<type>(std::move(xs)...);
                }
            };

            constexpr make_behavior_t make_behavior = make_behavior_t {};

            using behavior_impl_ptr = intrusive_ptr<behavior_impl>;

            // utility for getting a type-erased version of make_behavior
            struct make_behavior_impl_t {
                constexpr make_behavior_impl_t() {
                    // nop
                }

                template<class... Ts>
                behavior_impl_ptr operator()(Ts &&... xs) const {
                    return make_behavior(std::forward<Ts>(xs)...);
                }
            };

            constexpr make_behavior_impl_t make_behavior_impl = make_behavior_impl_t {};

        }    // namespace detail
    }        // namespace actor
}    // namespace nil
