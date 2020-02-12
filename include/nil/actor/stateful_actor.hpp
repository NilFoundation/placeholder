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

#include <new>
#include <type_traits>

#include <nil/actor/fwd.hpp>
#include <nil/actor/sec.hpp>

#include <nil/actor/logger.hpp>

#include <nil/actor/detail/type_traits.hpp>

namespace nil {
    namespace actor {

        /// An event-based actor with managed state. The state is constructed
        /// before `make_behavior` will get called and destroyed after the
        /// actor called `quit`. This state management brakes cycles and
        /// allows actors to automatically release ressources as soon
        /// as possible.
        template<class State, class Base /* = event_based_actor (see fwd.hpp) */>
        class stateful_actor : public Base {
        public:
            template<class... Ts>
            explicit stateful_actor(actor_config &cfg, Ts &&... xs) :
                Base(cfg, std::forward<Ts>(xs)...), state(state_) {
                cr_state(this);
            }

            ~stateful_actor() override {
                // nop
            }

            /// Destroys the state of this actor (no further overriding allowed).
            void on_exit() final {
                ACTOR_LOG_TRACE("");
                state_.~State();
            }

            const char *name() const final {
                return get_name(state_);
            }

            /// A reference to the actor's state.
            State &state;

            /// @cond PRIVATE

            void initialize() override {
                Base::initialize();
            }

            /// @endcond

        private:
            template<class T>
            typename std::enable_if<std::is_constructible<State, T>::value>::type cr_state(T arg) {
                new (&state_) State(arg);
            }

            template<class T>
            typename std::enable_if<!std::is_constructible<State, T>::value>::type cr_state(T) {
                new (&state_) State();
            }

            static const char *unbox_str(const char *str) {
                return str;
            }

            template<class U>
            static const char *unbox_str(const U &str) {
                return str.c_str();
            }

            template<class U>
            typename std::enable_if<detail::has_name<U>::value, const char *>::type get_name(const U &st) const {
                return unbox_str(st.name);
            }

            template<class U>
            typename std::enable_if<!detail::has_name<U>::value, const char *>::type get_name(const U &) const {
                return Base::name();
            }

            union {
                State state_;
            };
        };

    }    // namespace actor
}    // namespace nil
