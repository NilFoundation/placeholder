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

#include <vector>

#include <nil/actor/type_erased_value.hpp>

#include <nil/actor/detail/message_data.hpp>

namespace nil {
    namespace actor {
        namespace detail {

            class dynamic_message_data : public message_data {
            public:
                // -- member types -----------------------------------------------------------

                using elements = std::vector<type_erased_value_ptr>;

                // -- constructors, destructors, and assignment operators --------------------

                dynamic_message_data();

                dynamic_message_data(elements &&data);

                dynamic_message_data(const dynamic_message_data &other);

                ~dynamic_message_data() override;

                // -- overridden observers of message_data -----------------------------------

                dynamic_message_data *copy() const override;

                // -- overridden modifiers of type_erased_tuple ------------------------------

                void *get_mutable(size_t pos) override;

                error load(size_t pos, deserializer &source) override;

                error_code<sec> load(size_t pos, binary_deserializer &source) override;

                // -- overridden observers of type_erased_tuple ------------------------------

                size_t size() const noexcept override;

                uint32_t type_token() const noexcept override;

                rtti_pair type(size_t pos) const noexcept override;

                const void *get(size_t pos) const noexcept override;

                std::string stringify(size_t pos) const override;

                type_erased_value_ptr copy(size_t pos) const override;

                error save(size_t pos, serializer &sink) const override;

                error_code<sec> save(size_t pos, binary_serializer &sink) const override;

                // -- modifiers --------------------------------------------------------------

                void clear();

                void append(type_erased_value_ptr x);

                void add_to_type_token(uint16_t typenr);

            private:
                // -- data members -----------------------------------------------------------

                elements elements_;
                uint32_t type_token_;
            };

            void intrusive_ptr_add_ref(const dynamic_message_data *);

            void intrusive_ptr_release(const dynamic_message_data *);

            dynamic_message_data *intrusive_cow_ptr_unshare(dynamic_message_data *&);

        }    // namespace detail
    }        // namespace actor
}    // namespace nil
