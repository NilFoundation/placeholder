//---------------------------------------------------------------------------//
// Copyright (c) 2011-2020 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#pragma once

#include <cstdlib>

#include <nil/actor/fwd.hpp>
#include <nil/actor/type_id.hpp>

namespace nil::actor::detail {

    class BOOST_SYMBOL_VISIBLE type_id_list_builder {
    public:
        static constexpr size_t block_size = 8;

        type_id_list_builder();

        ~type_id_list_builder();

        void reserve(size_t new_capacity);

        void push_back(type_id_t id);

        /// Returns the number of elements currenty stored in the array.
        size_t size() const noexcept;

        /// @pre `index < size()`
        type_id_t operator[](size_t index) const noexcept;

        /// Convertes the internal buffer to a ::type_id_list and returns it.
        /// @pre `push_back` was called at least once
        type_id_list move_to_list();

        /// Convertes the internal buffer to a ::type_id_list and returns it.
        /// @pre `push_back` was called at least once
        type_id_list copy_to_list();

        void clear() noexcept {
            if (storage_)
                size_ = 1;
        }

    private:
        size_t size_;
        size_t reserved_;
        type_id_t *storage_;
    };

}    // namespace nil::actor::detail