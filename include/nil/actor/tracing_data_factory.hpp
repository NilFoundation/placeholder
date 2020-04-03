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


#include <nil/actor/fwd.hpp>

namespace nil {
    namespace actor {

        /// Creates instances of @ref tracing_data.
        class BOOST_SYMBOL_VISIBLE tracing_data_factory {
        public:
            virtual ~tracing_data_factory();

            /// Deserializes tracing data from `source` and either overrides the content
            /// of `dst` or allocates a new object if `dst` is null.
            /// @returns the result of `source`.
            virtual error deserialize(deserializer &source, std::unique_ptr<tracing_data> &dst) const = 0;

            /// @copydoc deserialize
            virtual error_code<sec> deserialize(binary_deserializer &source,
                                                std::unique_ptr<tracing_data> &dst) const = 0;
        };

    }    // namespace actor
}    // namespace nil
