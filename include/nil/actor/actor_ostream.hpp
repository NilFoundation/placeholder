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

#include <nil/actor/actor.hpp>
#include <nil/actor/deep_to_string.hpp>
#include <nil/actor/typed_actor_pointer.hpp>

namespace nil {
    namespace actor {

        /// Provides support for thread-safe output operations on character streams. The
        /// stream operates on a per-actor basis and will print only complete lines or
        /// when explicitly forced to flush its buffer. The stream will convert *any*
        /// operation to a message received by a printer actor. This actor is a sequence
        /// point that ensures output appears never interleaved.
        class actor_ostream {
        public:
            using fun_type = actor_ostream &(*)(actor_ostream &);

            actor_ostream(actor_ostream &&) = default;
            actor_ostream(const actor_ostream &) = default;
            actor_ostream &operator=(actor_ostream &&) = default;
            actor_ostream &operator=(const actor_ostream &) = default;

            /// Open redirection file in append mode.
            static constexpr int append = 0x01;

            explicit actor_ostream(local_actor *self);

            explicit actor_ostream(scoped_actor &self);

            template<class... Sigs>
            explicit actor_ostream(const typed_actor_pointer<Sigs...> &ptr) : actor_ostream(ptr.internal_ptr()) {
                // nop
            }

            /// Writes `arg` to the buffer allocated for the calling actor.
            actor_ostream &write(std::string arg);

            /// Flushes the buffer allocated for the calling actor.
            actor_ostream &flush();

            /// Redirects all further output from `self` to `file_name`.
            static void redirect(abstract_actor *self, std::string fn, int flags = 0);

            /// Redirects all further output from any actor that did not
            /// redirect its output to `fname`.
            static void redirect_all(spawner &sys, std::string fn, int flags = 0);

            /// Writes `arg` to the buffer allocated for the calling actor.
            inline actor_ostream &operator<<(const char *arg) {
                return write(arg);
            }

            /// Writes `arg` to the buffer allocated for the calling actor.
            inline actor_ostream &operator<<(std::string arg) {
                return write(std::move(arg));
            }

            /// Writes `to_string(arg)` to the buffer allocated for the calling actor,
            /// calling either `std::to_string` or `actor::to_string` depending on
            /// the argument.
            template<class T>
            inline actor_ostream &operator<<(const T &arg) {
                return write(deep_to_string(arg));
            }

            /// Apply `f` to `*this`.
            inline actor_ostream &operator<<(actor_ostream::fun_type f) {
                return f(*this);
            }

        private:
            void init(abstract_actor *);

            actor_id self_;
            actor printer_;
        };

        /// Convenience factory function for creating an actor output stream.
        actor_ostream aout(local_actor *self);

        /// Convenience factory function for creating an actor output stream.
        actor_ostream aout(scoped_actor &self);

        /// Convenience factory function for creating an actor output stream.
        template<class... Sigs>
        actor_ostream aout(const typed_actor_pointer<Sigs...> &ptr) {
            return actor_ostream {ptr};
        }

    }    // namespace actor
}    // namespace nil

namespace std {
    // provide convenience overlaods for aout; implemented in logging.cpp
    nil::actor::actor_ostream &endl(nil::actor::actor_ostream &o);
    nil::actor::actor_ostream &flush(nil::actor::actor_ostream &o);
}    // namespace std
