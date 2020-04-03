//---------------------------------------------------------------------------//
// Copyright (c) 2011-2019 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#pragma once

#include <nil/actor/credit_controller.hpp>

namespace nil {
    namespace actor {
        namespace detail {

            /// Computes predictable credit in unit tests.
            class test_credit_controller : public credit_controller {
            public:
                // -- member types -----------------------------------------------------------

                using super = credit_controller;

                // -- constructors, destructors, and assignment operators --------------------

                using super::super;

                ~test_credit_controller() override;

                // -- overrides --------------------------------------------------------------

                void before_processing(downstream_msg::batch &x) override;

                void after_processing(downstream_msg::batch &x) override;

                assignment compute_initial() override;

                assignment compute(timespan cycle, int32_t) override;

            private:
                /// Total number of elements in all processed batches in the current cycle.
                int64_t num_elements_ = 0;
            };

        }    // namespace detail
    }        // namespace actor
}    // namespace nil