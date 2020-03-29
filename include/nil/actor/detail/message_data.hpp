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

#include <atomic>
#include <cstdlib>

#include <nil/actor/byte.hpp>
#include <nil/actor/config.hpp>

#include <nil/actor/detail/implicit_conversions.hpp>
#include <nil/actor/detail/padded_size.hpp>
#include <nil/actor/fwd.hpp>
#include <nil/actor/type_id_list.hpp>

#ifdef ACTOR_CLANG
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc99-extensions"
#elif defined(ACTOR_MSVC)
#pragma warning(push)
#pragma warning(disable : 4200)
#endif

namespace nil::actor::detail {

    /// Container for storing an arbitrary number of message elements.
    class BOOST_SYMBOL_VISIBLE message_data {
    public:
        // -- constructors, destructors, and assignment operators --------------------

        message_data() = delete;

        message_data(const message_data &) = delete;

        message_data &operator=(const message_data &) = delete;

        /// Constructs the message data object *without* constructing any element.
        explicit message_data(type_id_list types);

        ~message_data() noexcept;

        message_data *copy() const;

        // -- reference counting -----------------------------------------------------

        /// Increases reference count by one.
        void ref() const noexcept {
            rc_.fetch_add(1, std::memory_order_relaxed);
        }

        /// Decreases the reference count by one and destroys the object when its
        /// reference count drops to zero.
        void deref() noexcept {
            if (unique() || rc_.fetch_sub(1, std::memory_order_acq_rel) == 1) {
                this->~message_data();
                free(const_cast<message_data *>(this));
            }
        }

        // -- properties -------------------------------------------------------------

        /// Queries whether there is exactly one reference to this data.
        bool unique() const noexcept {
            return rc_ == 1;
        }

        /// Returns the current number of references to this data.
        size_t get_reference_count() const noexcept {
            return rc_.load();
        }

        /// Returns the memory region for storing the message elements.
        byte *storage() noexcept {
            return storage_;
        }

        /// @copydoc storage
        const byte *storage() const noexcept {
            return storage_;
        }

        /// Returns the type IDs of the message elements.
        auto types() const noexcept {
            return types_;
        }

        /// Returns the number of elements.
        auto size() const noexcept {
            return types_.size();
        }

        /// Returns the memory location for the object at given index.
        /// @pre `index < size()`
        byte *at(size_t index) noexcept;

        /// @copydoc at
        const byte *at(size_t index) const noexcept;

        nil::actor::error save(nil::actor::serializer &sink) const;

        nil::actor::error save(nil::actor::binary_serializer &sink) const;

        nil::actor::error load(nil::actor::deserializer &source);

        nil::actor::error load(nil::actor::binary_deserializer &source);

    private:
        mutable std::atomic<size_t> rc_;
        type_id_list types_;
        byte storage_[];
    };

    // -- related non-members ------------------------------------------------------

    /// @relates message_data
    inline void intrusive_ptr_add_ref(const message_data *ptr) {
        ptr->ref();
    }

    /// @relates message_data
    inline void intrusive_ptr_release(message_data *ptr) {
        ptr->deref();
    }

    inline void message_data_init(byte *) {
        // nop
    }

    template<class T, class... Ts>
    void message_data_init(byte *storage, T &&x, Ts &&... xs) {
        // TODO: exception safety: if any constructor throws, we need to unwind the
        //       stack here and call destructors.
        using type = strip_and_convert_t<T>;
        new (storage) type(std::forward<T>(x));
        message_data_init(storage + padded_size_v<type>, std::forward<Ts>(xs)...);
    }

}    // namespace nil::actor::detail


#ifdef ACTOR_CLANG
#pragma clang diagnostic pop
#elif defined(MSVC)
#pragma warning(pop)
#endif