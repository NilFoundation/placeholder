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
#include <chrono>

#include <nil/actor/fwd.hpp>
#include <nil/actor/actor.hpp>
#include <nil/actor/message.hpp>
#include <nil/actor/duration.hpp>
#include <nil/actor/message_id.hpp>
#include <nil/actor/response_type.hpp>
#include <nil/actor/response_handle.hpp>
#include <nil/actor/message_priority.hpp>
#include <nil/actor/check_typed_input.hpp>

namespace nil {
    namespace actor {
        namespace mixin {

            template<class T>
            struct is_blocking_requester : std::false_type {};

            /// A `requester` is an actor that supports
            /// `self->request(...).{then|await|receive}`.
            template<class Base, class Subtype>
            class requester : public Base {
            public:
                // -- member types -----------------------------------------------------------

                using extended_base = requester;

                // -- constructors, destructors, and assignment operators --------------------

                template<class... Ts>
                requester(Ts &&... xs) : Base(std::forward<Ts>(xs)...) {
                    // nop
                }

                // -- request ----------------------------------------------------------------

                /// Sends `{xs...}` as a synchronous message to `dest` with priority `mp`.
                /// @returns A handle identifying a future-like handle to the response.
                /// @warning The returned handle is actor specific and the response to the
                ///          sent message cannot be received by another actor.
                template<message_priority P = message_priority::normal, class Handle = actor, class... Ts>
                response_handle<
                    Subtype,
                    response_type_t<typename Handle::signatures,
                                    typename detail::implicit_conversions<typename std::decay<Ts>::type>::type...>,
                    is_blocking_requester<Subtype>::value>
                    request(const Handle &dest, const duration &timeout, Ts &&... xs) {
                    static_assert(sizeof...(Ts) > 0, "no message to send");
                    using token = detail::type_list<
                        typename detail::implicit_conversions<typename std::decay<Ts>::type>::type...>;
                    static_assert(response_type_unbox<signatures_of_t<Handle>, token>::valid,
                                  "receiver does not accept given message");
                    auto dptr = static_cast<Subtype *>(this);
                    auto req_id = dptr->new_request_id(P);
                    if (dest) {
                        dest->eq_impl(req_id, dptr->ctrl(), dptr->context(), std::forward<Ts>(xs)...);
                        dptr->request_response_timeout(timeout, req_id);
                    } else {
                        dptr->eq_impl(req_id.response_id(), dptr->ctrl(), dptr->context(),
                                      make_error(sec::invalid_argument));
                    }
                    return {req_id.response_id(), dptr};
                }

                /// Sends `{xs...}` as a synchronous message to `dest` with priority `mp`.
                /// @returns A handle identifying a future-like handle to the response.
                /// @warning The returned handle is actor specific and the response to the
                ///          sent message cannot be received by another actor.
                template<message_priority P = message_priority::normal, class Rep = int, class Period = std::ratio<1>,
                         class Handle = actor, class... Ts>
                response_handle<
                    Subtype,
                    response_type_t<typename Handle::signatures,
                                    typename detail::implicit_conversions<typename std::decay<Ts>::type>::type...>,
                    is_blocking_requester<Subtype>::value>
                    request(const Handle &dest, std::chrono::duration<Rep, Period> timeout, Ts &&... xs) {
                    return request(dest, duration {timeout}, std::forward<Ts>(xs)...);
                }
            };

        }    // namespace mixin
    }        // namespace actor
}    // namespace nil
