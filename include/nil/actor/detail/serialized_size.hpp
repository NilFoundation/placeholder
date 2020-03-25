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

#include <nil/actor/error.hpp>
#include <nil/actor/serialization/serializer.hpp>

namespace nil {
    namespace actor {
        namespace detail {

            class serialized_size_inspector final : public serializer {
            public:
                using super = serializer;

                using super::super;

                size_t result() const noexcept {
                    return result_;
                }

                result_type begin_object(uint16_t typenr, string_view type_name) override;

                result_type end_object() override;

                result_type begin_sequence(size_t num) override;

                result_type end_sequence() override;

                result_type apply(bool x) override;

                result_type apply(int8_t x) override;

                result_type apply(uint8_t x) override;

                result_type apply(int16_t x) override;

                result_type apply(uint16_t x) override;

                result_type apply(int32_t x) override;

                result_type apply(uint32_t x) override;

                result_type apply(int64_t x) override;

                result_type apply(uint64_t x) override;

                result_type apply(float x) override;

                result_type apply(double x) override;

                result_type apply(long double x) override;

                result_type apply(string_view x) override;

                result_type apply(std::u16string_view x) override;

                result_type apply(std::u32string_view x) override;

                result_type apply(span<const byte> x) override;

                result_type apply(const std::vector<bool> &xs) override;

            private:
                size_t result_ = 0;
            };

            template<class T>
            size_t serialized_size(spawner &sys, const T &x) {
                serialized_size_inspector f {sys};
                auto err = f(x);
                static_cast<void>(err);
                return f.result();
            }

        }    // namespace detail
    }        // namespace actor
}    // namespace nil