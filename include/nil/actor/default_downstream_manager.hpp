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

#pragma once

#include <nil/actor/broadcast_downstream_manager.hpp>
#include <nil/actor/stream_source_trait.hpp>
#include <nil/actor/stream_stage_trait.hpp>

#include <nil/actor/detail/type_traits.hpp>

namespace nil {
    namespace actor {

        /// Selects a downstream manager implementation based on the signature of
        /// various handlers.
        template<class F>
        struct default_downstream_manager {
            /// The function signature of `F`.
            using fun_sig = typename detail::get_callable_trait<F>::fun_sig;

            /// The source trait for `F`.
            using source_trait = stream_source_trait<fun_sig>;

            /// The stage trait for `F`.
            using stage_trait = stream_stage_trait<fun_sig>;

            /// The output type as returned by the source or stage trait.
            using output_type = typename std::conditional<source_trait::valid, typename source_trait::output,
                                                          typename stage_trait::output>::type;

            /// The default downstream manager deduced by this trait.
            using type = broadcast_downstream_manager<output_type>;
        };

        template<class F>
        using default_downstream_manager_t = typename default_downstream_manager<F>::type;

    }    // namespace actor
}    // namespace nil
