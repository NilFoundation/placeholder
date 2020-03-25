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

#include <nil/actor/config.hpp>
#include <nil/actor/ref_counted.hpp>

#include <nil/actor/detail/type_list.hpp>

#include <nil/actor/detail/tuple_vals.hpp>
#include <nil/actor/detail/message_data.hpp>

namespace nil {
    namespace actor {
        namespace detail {

            class decorated_tuple : public message_data {
            public:
                // -- member types -----------------------------------------------------------

                using message_data::cow_ptr;

                using vector_type = std::vector<size_t>;

                // -- constructors, destructors, and assignment operators --------------------

                decorated_tuple(cow_ptr &&, vector_type &&);

                static cow_ptr make(cow_ptr d, vector_type v);

                decorated_tuple &operator=(const decorated_tuple &) = delete;

                // -- overridden observers of message_data -----------------------------------

                message_data *copy() const override;

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

                // -- inline observers -------------------------------------------------------

                inline const cow_ptr &decorated() const {
                    return decorated_;
                }

                inline const vector_type &mapping() const {
                    return mapping_;
                }

            private:
                // -- constructors, destructors, and assignment operators --------------------

                decorated_tuple(const decorated_tuple &) = default;

                // -- data members -----------------------------------------------------------

                cow_ptr decorated_;
                vector_type mapping_;
                uint32_t type_token_;
            };
        }    // namespace detail
    }        // namespace actor
}    // namespace nil
