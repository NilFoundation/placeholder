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

// The rationale of this header is to provide a serialization API
// that is compatbile to boost.serialization. In particular, the
// design goals are:
// - allow users to integrate existing boost.serialization-based code easily
// - allow to switch out this header with the actual boost header in boost.actor
//
// Differences in semantics are:
// - ACTOR does *not* respect class versions
// - the `unsigned int` argument is always 0 and ignored by ACTOR
//
// Since ACTOR requires all runtime instances to have the same types
// announced, different class versions in a single actor system would
// cause inconsistencies that are not recoverable.

#pragma once

#include <utility>
#include <type_traits>

#include <nil/actor/detail/type_traits.hpp>

namespace boost {
    namespace serialization {}    // namespace serialization
}    // namespace boost

namespace nil {
    namespace actor {
        namespace detail {

            // Calls `serialize(...)` with `using namespace boost::serialization`
            // to enable both ADL and picking up existing boost code.

            template<class Processor, class U>
            auto delegate_serialize(Processor &proc, U &x, const unsigned int y = 0)
                -> decltype(serialize(proc, x, y)) {
                using namespace boost::serialization;
                serialize(proc, x, y);
            }

            // Calls `serialize(...)` without the unused version argument, which ACTOR
            // ignores anyway.

            template<class Processor, class U>
            auto delegate_serialize(Processor &proc, U &x) -> decltype(serialize(proc, x)) {
                serialize(proc, x);
            }

        }    // namespace detail
    }        // namespace actor
}    // namespace nil