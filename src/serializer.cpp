//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#include <nil/actor/serializer.hpp>

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
