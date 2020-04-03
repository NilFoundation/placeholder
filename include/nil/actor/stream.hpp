//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#pragma once

#include <nil/actor/fwd.hpp>
#include <nil/actor/invalid_stream.hpp>
#include <nil/actor/meta/type_name.hpp>
#include <nil/actor/stream_manager.hpp>
#include <nil/actor/stream_slot.hpp>
#include <nil/actor/type_id.hpp>

namespace nil {
    namespace actor {

        /// Empty marker type for streaming handshakes.
        template<class T>
        class stream {
        public:
            using value_type = T;
        };

        /// @relates stream
        template<class Inspector, class T>
        auto inspect(Inspector &f, stream<T> &) {
            return f(meta::type_name(type_name_v<stream<T>>));
        }

    }    // namespace actor
}    // namespace nil
