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

#include <string>
#include <iterator>
#include <typeinfo>

#include <nil/actor/config.hpp>
#include <nil/actor/fwd.hpp>
#include <nil/actor/intrusive_cow_ptr.hpp>
#include <nil/actor/intrusive_ptr.hpp>
#include <nil/actor/ref_counted.hpp>
#include <nil/actor/type_erased_tuple.hpp>

#include <nil/actor/detail/type_list.hpp>

namespace nil {
    namespace actor {
        namespace detail {

            class message_data : public ref_counted, public type_erased_tuple {
            public:
                // -- nested types -----------------------------------------------------------

                using cow_ptr = intrusive_cow_ptr<message_data>;

                // -- constructors, destructors, and assignment operators --------------------

                message_data() = default;
                message_data(const message_data &) = default;

                ~message_data() override;

                // -- pure virtual observers -------------------------------------------------

                virtual message_data *copy() const = 0;

                // -- observers --------------------------------------------------------------

                using type_erased_tuple::copy;

                bool shared() const noexcept override;
            };
        }    // namespace detail
    }        // namespace actor
}    // namespace nil
