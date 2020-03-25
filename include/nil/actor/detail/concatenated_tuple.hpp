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

#include <vector>
#include <algorithm>

#include <nil/actor/detail/decorated_tuple.hpp>

namespace nil {
    namespace actor {
        namespace detail {

            class concatenated_tuple : public message_data {
            public:
                // -- member types -----------------------------------------------------------

                using message_data::cow_ptr;

                using vector_type = std::vector<cow_ptr>;

                // -- constructors, destructors, and assignment operators --------------------

                concatenated_tuple(std::initializer_list<cow_ptr> xs);

                static cow_ptr make(std::initializer_list<cow_ptr> xs);

                concatenated_tuple(const concatenated_tuple &) = default;

                concatenated_tuple &operator=(const concatenated_tuple &) = delete;

                // -- overridden observers of message_data -----------------------------------

                concatenated_tuple *copy() const override;

                // -- overridden modifiers of type_erased_tuple ------------------------------

                void *get_mutable(size_t pos) override;

                error load(size_t pos, deserializer &source) override;

                // -- overridden observers of type_erased_tuple ------------------------------

                size_t size() const noexcept override;

                uint32_t type_token() const noexcept override;

                rtti_pair type(size_t pos) const noexcept override;

                const void *get(size_t pos) const noexcept override;

                std::string stringify(size_t pos) const override;

                type_erased_value_ptr copy(size_t pos) const override;

                error save(size_t pos, serializer &sink) const override;

                // -- element access ---------------------------------------------------------

                std::pair<message_data *, size_t> select(size_t pos);

                std::pair<const message_data *, size_t> select(size_t pos) const;

            private:
                // -- data members -----------------------------------------------------------

                vector_type data_;
                uint32_t type_token_;
                size_t size_;
            };

        }    // namespace detail
    }        // namespace actor
}    // namespace nil
