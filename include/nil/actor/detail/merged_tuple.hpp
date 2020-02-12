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

#include <nil/actor/message.hpp>
#include <nil/actor/actor_addr.hpp>
#include <nil/actor/attachable.hpp>
#include <nil/actor/abstract_actor.hpp>

namespace nil {
    namespace actor {
        namespace detail {

            class merged_tuple : public message_data {
            public:
                // -- member types -----------------------------------------------------------

                using message_data::cow_ptr;

                using data_type = std::vector<cow_ptr>;

                using mapping_type = std::vector<std::pair<size_t, size_t>>;

                // -- constructors, destructors, and assignment operators --------------------

                static cow_ptr make(message x, message y);

                merged_tuple(data_type xs, mapping_type ys);

                merged_tuple &operator=(const merged_tuple &) = delete;

                // -- overridden observers of message_data -----------------------------------

                merged_tuple *copy() const override;

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

                // -- observers --------------------------------------------------------------

                const mapping_type &mapping() const;

            private:
                // -- constructors, destructors, and assignment operators --------------------

                merged_tuple(const merged_tuple &) = default;

                // -- data members -----------------------------------------------------------

                data_type data_;
                uint32_t type_token_;
                mapping_type mapping_;
            };

        }    // namespace detail
    }        // namespace actor
}    // namespace nil
