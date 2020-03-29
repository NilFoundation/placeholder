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

#include <chrono>
#include <tuple>
#include <type_traits>


#include <nil/actor/timeout_definition.hpp>
#include <nil/actor/timespan.hpp>

namespace nil {
    namespace actor {

        class BOOST_SYMBOL_VISIBLE timeout_definition_builder {
        public:
            explicit constexpr timeout_definition_builder(timespan d) : tout_(d) {
                // nop
            }

            template<class F>
            timeout_definition<F> operator>>(F f) const {
                return {tout_, std::move(f)};
            }

        private:
            timespan tout_;
        };

        /// Returns a generator for timeouts.
        template<class Rep, class Period>
        constexpr auto after(std::chrono::duration<Rep, Period> d) {
            using std::chrono::duration_cast;
            return timeout_definition_builder {duration_cast<timespan>(d)};
        }

    }    // namespace actor
}    // namespace nil
