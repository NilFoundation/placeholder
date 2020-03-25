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
#include <type_traits>

#include <nil/actor/timeout_definition.hpp>

namespace nil {
    namespace actor {

        class timeout_definition_builder {
        public:
            constexpr timeout_definition_builder(duration d) : tout_(d) {
                // nop
            }

            template<class F>
            timeout_definition<F> operator>>(F f) const {
                return {tout_, std::move(f)};
            }

        private:
            duration tout_;
        };

        /// Returns a generator for timeouts.
        constexpr timeout_definition_builder after(duration d) {
            return {d};
        }

        /// Returns a generator for timeouts.
        template<class Rep, class Period>
        constexpr timeout_definition_builder after(std::chrono::duration<Rep, Period> d) {
            return after(duration {d});
        }

    }    // namespace actor
}    // namespace nil
