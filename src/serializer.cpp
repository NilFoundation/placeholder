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

#include <nil/actor/serialization/serializer.hpp>

#include <nil/actor/spawner.hpp>

namespace nil {
    namespace actor {

        serializer::serializer(spawner &sys) noexcept : context_(sys.dummy_execution_unit()) {
            // nop
        }

        serializer::serializer(execution_unit *ctx) noexcept : context_(ctx) {
            // nop
        }

        serializer::~serializer() {
            // nop
        }

        auto serializer::apply(const std::vector<bool> &xs) -> result_type {
            if (auto err = begin_sequence(xs.size()))
                return err;
            for (bool value : xs)
                if (auto err = apply(value))
                    return err;
            return end_sequence();
        }
    }    // namespace actor
}    // namespace nil
