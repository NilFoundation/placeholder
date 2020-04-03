//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

// This file is partially included in the manual, do not modify
// without updating the references in the *.tex files!
// Manual references: lines 29-49 (Error.tex)

#pragma once

#include <cstdint>
#include <string>

#include <boost/config.hpp>

#include <nil/actor/error_category.hpp>

namespace nil {
    namespace actor {

        /// This error category represents fail conditions for actors.
        enum class exit_reason : uint8_t {
            /// Indicates that an actor finished execution without error.
            normal = 0,
            /// Indicates that an actor died because of an unhandled exception.
            unhandled_exception,
            /// Indicates that the exit reason for this actor is unknown, i.e.,
            /// the actor has been terminated and no longer exists.
            unknown,
            /// Indicates that an actor pool unexpectedly ran out of workers.
            out_of_workers,
            /// Indicates that an actor was forced to shutdown by a user-generated event.
            user_shutdown,
            /// Indicates that an actor was killed unconditionally.
            kill,
            /// Indicates that an actor finishied execution because a connection
            /// to a remote link was closed unexpectedly.
            remote_link_unreachable,
            /// Indicates that an actor was killed because it became unreachable.
            unreachable
        };

        /// Returns a string representation of given exit reason.
        BOOST_SYMBOL_VISIBLE std::string to_string(exit_reason);

        template<>
        struct error_category<exit_reason> {
            static constexpr uint8_t value = 3;
        };

    }    // namespace actor
}    // namespace nil
