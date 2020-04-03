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

#include <memory>


#include <nil/actor/fwd.hpp>

namespace nil {
    namespace actor {

        /// Marker interface for application-specific tracing data. This interface
        /// enables users to inject application-specific instrumentation into CAF's
        /// messaging layer. CAF provides no default implementation for this
        /// customization point.
        class BOOST_SYMBOL_VISIBLE tracing_data {
        public:
            virtual ~tracing_data();

            /// Writes the content of this object to `sink`.
            virtual error serialize(serializer &sink) const = 0;

            /// @copydoc serialize
            virtual error_code<sec> serialize(binary_serializer &sink) const = 0;
        };

        /// @relates tracing_data
        using tracing_data_ptr = std::unique_ptr<tracing_data>;

        /// @relates tracing_data
        BOOST_SYMBOL_VISIBLE error inspect(serializer &sink, const tracing_data_ptr &x);

        /// @relates tracing_data
        BOOST_SYMBOL_VISIBLE error_code<sec> inspect(binary_serializer &sink, const tracing_data_ptr &x);

        /// @relates tracing_data
        BOOST_SYMBOL_VISIBLE error inspect(deserializer &source, tracing_data_ptr &x);

        /// @relates tracing_data
        BOOST_SYMBOL_VISIBLE error_code<sec> inspect(binary_deserializer &source, tracing_data_ptr &x);

    }    // namespace actor
}    // namespace nil
