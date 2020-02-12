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
#include <cstddef>
#include <utility>
#include <type_traits>

#include <nil/actor/fwd.hpp>
#include <nil/actor/raise_error.hpp>
#include <nil/actor/write_inspector.hpp>

namespace nil {
    namespace actor {

        /// @ingroup TypeSystem
        /// Technology-independent deserialization interface.
        class deserializer : public write_inspector<deserializer> {
        public:
            // -- member types -----------------------------------------------------------

            using result_type = error;

            // -- constructors, destructors, and assignment operators --------------------

            explicit deserializer(spawner &sys) noexcept;

            explicit deserializer(execution_unit *ctx = nullptr) noexcept;

            virtual ~deserializer();

            // -- properties -------------------------------------------------------------

            execution_unit *context() const noexcept {
                return context_;
            }

            // -- interface functions ----------------------------------------------------

            /// Begins processing of an object. Saves the type information
            /// to the underlying storage.
            virtual result_type begin_object(uint16_t &typenr, std::string &type_name) = 0;

            /// Ends processing of an object.
            virtual result_type end_object() = 0;

            /// Begins processing of a sequence. Saves the size
            /// to the underlying storage when in saving mode, otherwise
            /// sets `num` accordingly.
            virtual result_type begin_sequence(size_t &num) = 0;

            /// Ends processing of a sequence.
            virtual result_type end_sequence() = 0;

            /// Reads primitive value from the input.
            /// @param x The primitive value.
            /// @returns A non-zero error code on failure, `sec::success` otherwise.
            virtual result_type apply(bool &x) = 0;

            /// @copydoc apply
            virtual result_type apply(int8_t &) = 0;

            /// @copydoc apply
            virtual result_type apply(uint8_t &) = 0;

            /// @copydoc apply
            virtual result_type apply(int16_t &) = 0;

            /// @copydoc apply
            virtual result_type apply(uint16_t &) = 0;

            /// @copydoc apply
            virtual result_type apply(int32_t &) = 0;

            /// @copydoc apply
            virtual result_type apply(uint32_t &) = 0;

            /// @copydoc apply
            virtual result_type apply(int64_t &) = 0;

            /// @copydoc apply
            virtual result_type apply(uint64_t &) = 0;

            /// @copydoc apply
            virtual result_type apply(float &) = 0;

            /// @copydoc apply
            virtual result_type apply(double &) = 0;

            /// @copydoc apply
            virtual result_type apply(long double &) = 0;

            /// @copydoc apply
            virtual result_type apply(timespan x) = 0;

            /// @copydoc apply
            virtual result_type apply(timestamp x) = 0;

            /// @copydoc apply
            virtual result_type apply(atom_value x) = 0;

            /// @copydoc apply
            virtual result_type apply(std::string &) = 0;

            /// @copydoc apply
            virtual result_type apply(std::u16string &) = 0;

            /// @copydoc apply
            virtual result_type apply(std::u32string &) = 0;

            /// @copydoc apply
            template<class Enum, typename = typename std::enable_if<std::is_enum<Enum>::value>::type>
            auto apply(Enum &x) {
                return apply(reinterpret_cast<typename std::underlying_type<Enum>::type &>(x));
            }

            /// Reads a byte sequence from the input.
            /// @param x The byte sequence.
            /// @returns A non-zero error code on failure, `sec::success` otherwise.
            virtual result_type apply_raw(span<byte> x) = 0;

            /// Adds each boolean in `xs` to the output. Derived classes can override this
            /// member function to pack the booleans, for example to avoid using one byte
            /// for each value in a binary output format.
            virtual result_type apply(std::vector<bool> &xs) noexcept;

        protected:
            /// Provides access to the ::proxy_registry and to the ::spawner.
            execution_unit *context_;
        };
    }    // namespace actor
}    // namespace nil
