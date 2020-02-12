//---------------------------------------------------------------------------//
// Copyright (c) 2011-2019 Dominik Charousset
// Copyright (c) 2019 Nil Foundation AG
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE and LICENSE_ALTERNATIVE.
//---------------------------------------------------------------------------//

#include <nil/actor/error_code.hpp>

namespace nil {
    namespace actor {
        namespace detail {

            /// @addtogroup BASP

            /// Storage type for raw bytes.
            using buffer_type = std::vector<char>;

            /// @}

        }    // namespace detail
    }        // namespace actor
}    // namespace nil
