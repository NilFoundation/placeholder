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

#include <string>
#include <cstddef>    // size_t
#include <type_traits>

#include <nil/actor/fwd.hpp>
#include <nil/actor/error.hpp>
#include <nil/actor/raise_error.hpp>
#include <nil/actor/read_inspector.hpp>

namespace nil {
    namespace actor {

        /// @ingroup TypeSystem
        /// Technology-independent serialization interface.
        class serializer : public read_inspector<serializer> {
        public:
            // -- member types -----------------------------------------------------------

            using result_type = error;

            // -- constructors, destructors, and assignment operators --------------------

            explicit serializer(spawner &sys) noexcept;

            explicit serializer(execution_unit *ctx = nullptr) noexcept;

            virtual ~serializer();

            // -- properties -------------------------------------------------------------

            auto context() const noexcept {
                return context_;
            }

            // -- interface functions ----------------------------------------------------

            /// Begins processing of an object. Saves the type information
            /// to the underlying storage.
            virtual result_type begin_object(uint16_t typenr, string_view type_name) = 0;

            /// Ends processing of an object.
            virtual result_type end_object() = 0;

            /// Begins processing of a sequence. Saves the size
            /// to the underlying storage when in saving mode, otherwise
            /// sets `num` accordingly.
            virtual result_type begin_sequence(size_t num) = 0;

            /// Ends processing of a sequence.
            virtual result_type end_sequence() = 0;

            /// Adds the primitive type `x` to the output.
            /// @param x The primitive value.
            /// @returns A non-zero error code on failure, `sec::success` otherwise.
            virtual result_type apply(bool x) = 0;

            /// @copydoc apply
            virtual result_type apply(int8_t x) = 0;

            /// @copydoc apply
            virtual result_type apply(uint8_t x) = 0;

            /// @copydoc apply
            virtual result_type apply(int16_t x) = 0;

            /// @copydoc apply
            virtual result_type apply(uint16_t x) = 0;

            /// @copydoc apply
            virtual result_type apply(int32_t x) = 0;

            /// @copydoc apply
            virtual result_type apply(uint32_t x) = 0;

            /// @copydoc apply
            virtual result_type apply(int64_t x) = 0;

            /// @copydoc apply
            virtual result_type apply(uint64_t x) = 0;

            /// @copydoc apply
            virtual result_type apply(float x) = 0;

            /// @copydoc apply
            virtual result_type apply(double x) = 0;

            /// @copydoc apply
            virtual result_type apply(long double x) = 0;

            /// @copydoc apply
            virtual result_type apply(timespan x) = 0;

            /// @copydoc apply
            virtual result_type apply(timestamp x) = 0;

            /// @copydoc apply
            virtual result_type apply(atom_value x) = 0;

            /// @copydoc apply
            virtual result_type apply(string_view x) = 0;

            /// @copydoc apply
            virtual result_type apply(std::u16string_view x) = 0;

            /// @copydoc apply
            virtual result_type apply(std::u32string_view x) = 0;

            template<class Enum, typename = typename std::enable_if<std::is_enum<Enum>::value>::type>
            result_type apply(Enum x) {
                return apply(static_cast<typename std::underlying_type<Enum>::type>(x));
            }

            /// Adds `x` as raw byte block to the output.
            /// @param x The byte sequence.
            /// @returns A non-zero error code on failure, `sec::success` otherwise.
            virtual result_type apply(span<const byte> x) = 0;

            /// Adds each boolean in `xs` to the output. Derived classes can override this
            /// member function to pack the booleans, for example to avoid using one byte
            /// for each value in a binary output format.
            virtual result_type apply(const std::vector<bool> &xs);

        protected:
            /// Provides access to the ::proxy_registry and to the ::spawner.
            execution_unit *context_;
        };
    }    // namespace actor
}    // namespace nil
