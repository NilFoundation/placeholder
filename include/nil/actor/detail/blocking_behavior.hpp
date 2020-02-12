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

#include <nil/actor/behavior.hpp>
#include <nil/actor/catch_all.hpp>
#include <nil/actor/timeout_definition.hpp>

namespace nil {
    namespace actor {
        namespace detail {

            class blocking_behavior {
            public:
                behavior &nested;

                blocking_behavior(behavior &x);
                blocking_behavior(blocking_behavior &&) = default;

                virtual ~blocking_behavior();

                virtual result<message> fallback(message_view &);

                virtual duration timeout();

                virtual void handle_timeout();
            };

            template<class F>
            class blocking_behavior_v2 : public blocking_behavior {
            public:
                catch_all<F> f;

                blocking_behavior_v2(behavior &x, catch_all<F> y) : blocking_behavior(x), f(std::move(y)) {
                    // nop
                }

                blocking_behavior_v2(blocking_behavior_v2 &&) = default;

                result<message> fallback(message_view &x) override {
                    return f.handler(x);
                }
            };

            template<class F>
            class blocking_behavior_v3 : public blocking_behavior {
            public:
                timeout_definition<F> f;

                blocking_behavior_v3(behavior &x, timeout_definition<F> y) : blocking_behavior(x), f(std::move(y)) {
                    // nop
                }

                blocking_behavior_v3(blocking_behavior_v3 &&) = default;

                duration timeout() override {
                    return f.timeout;
                }

                void handle_timeout() override {
                    f.handler();
                }
            };

            template<class F1, class F2>
            class blocking_behavior_v4 : public blocking_behavior {
            public:
                catch_all<F1> f1;
                timeout_definition<F2> f2;

                blocking_behavior_v4(behavior &x, catch_all<F1> y, timeout_definition<F2> z) :
                    blocking_behavior(x), f1(std::move(y)), f2(std::move(z)) {
                    // nop
                }

                blocking_behavior_v4(blocking_behavior_v4 &&) = default;

                result<message> fallback(message_view &x) override {
                    return f1.handler(x);
                }

                duration timeout() override {
                    return f2.timeout;
                }

                void handle_timeout() override {
                    f2.handler();
                }
            };

            struct make_blocking_behavior_t {
                constexpr make_blocking_behavior_t() {
                    // nop
                }

                inline blocking_behavior operator()(behavior *x) const {
                    ACTOR_ASSERT(x != nullptr);
                    return {*x};
                }

                template<class F>
                blocking_behavior_v2<F> operator()(behavior *x, catch_all<F> y) const {
                    ACTOR_ASSERT(x != nullptr);
                    return {*x, std::move(y)};
                }

                template<class F>
                blocking_behavior_v3<F> operator()(behavior *x, timeout_definition<F> y) const {
                    ACTOR_ASSERT(x != nullptr);
                    return {*x, std::move(y)};
                }

                template<class F1, class F2>
                blocking_behavior_v4<F1, F2> operator()(behavior *x, catch_all<F1> y, timeout_definition<F2> z) const {
                    ACTOR_ASSERT(x != nullptr);
                    return {*x, std::move(y), std::move(z)};
                }
            };

            constexpr make_blocking_behavior_t make_blocking_behavior = make_blocking_behavior_t {};

        }    // namespace detail
    }        // namespace actor
}    // namespace nil
