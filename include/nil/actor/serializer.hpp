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

#include <cstddef>
#include <cstdint>
#include <string>
#include <tuple>
#include <utility>

#include <nil/actor/byte.hpp>

#include <nil/actor/fwd.hpp>
#include <nil/actor/meta/annotation.hpp>
#include <nil/actor/meta/save_callback.hpp>
#include <nil/actor/read_inspector.hpp>
#include <nil/actor/sec.hpp>
#include <nil/actor/span.hpp>
#include <nil/actor/string_view.hpp>

namespace nil {
    namespace actor {

        /// @ingroup TypeSystem
        /// Technology-independent serialization interface.
        class BOOST_SYMBOL_VISIBLE serializer : public read_inspector<serializer> {
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
            virtual result_type begin_object(type_id_t type) = 0;

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
            virtual result_type apply(string_view x) = 0;

            /// @copydoc apply
            virtual result_type apply(const std::u16string &x) = 0;

            /// @copydoc apply
            virtual result_type apply(const std::u32string &x) = 0;

            template<class Enum, class = std::enable_if_t<std::is_enum<Enum>::value>>
            auto apply(Enum x) {
                return apply(static_cast<std::underlying_type_t<Enum>>(x));
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
