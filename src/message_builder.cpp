//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#include <nil/actor/message_builder.hpp>

namespace nil {
    namespace actor {

        void message_builder::clear() noexcept {
            types_.clear();
            elements_.clear();
        }

        message message_builder::to_message() const {
            // TODO: implement me
            return {};
        }

        message message_builder::move_to_message() {
            // TODO: implement me
            return {};
        }

    }    // namespace actor
}    // namespace nil
