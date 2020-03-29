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

#include <memory>
#include <new>

#include <nil/actor/byte.hpp>

#include <nil/actor/detail/padded_size.hpp>

namespace nil::actor::detail {

    /// Wraps a value for either copying or moving it into a pre-allocated storage
    /// later.
    class BOOST_SYMBOL_VISIBLE message_builder_element {
    public:
        virtual ~message_builder_element();

        /// Uses placement new to create a copy of the wrapped value at given memory
        /// region.
        /// @returns the past-the-end pointer of the object, i.e., the first byte for
        ///          the *next* object.
        virtual byte *copy_init(byte *storage) const = 0;

        /// Uses placement new to move the wrapped value to given memory region.
        /// @returns the past-the-end pointer of the object, i.e., the first byte for
        ///          the *next* object.
        virtual byte *move_init(byte *storage) = 0;
    };

    template<class T>
    class message_builder_element_impl : public message_builder_element {
    public:
        message_builder_element_impl(T value) : value_(std::move(value)) {
            // nop
        }

        byte *copy_init(byte *storage) const override {
            new (storage) T(value_);
            return storage + padded_size_v<T>;
        }

        byte *move_init(byte *storage) override {
            new (storage) T(std::move(value_));
            return storage + padded_size_v<T>;
        }

    private:
        T value_;
    };

    using message_builder_element_ptr = std::unique_ptr<message_builder_element>;

    template<class T>
    auto make_message_builder_element(T &&x) {
        using impl = message_builder_element_impl<std::decay_t<T>>;
        return message_builder_element_ptr {new impl(std::forward<T>(x))};
    }

}    // namespace nil::actor::detail