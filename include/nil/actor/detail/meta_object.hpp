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

#include <cstddef>
#include <cstdint>

#include <nil/actor/fwd.hpp>
#include <nil/actor/span.hpp>

namespace nil::actor::detail {

    /// Enables destroying, construcing and serializing objects through type-erased
    /// pointers.
    struct meta_object {
        /// Stores a human-readable representation of the type's name.
        const char *type_name = nullptr;

        /// Stores how many Bytes objects of this type require, including padding for
        /// aligning to `max_align_t`.
        size_t padded_size;

        /// Calls the destructor for given object.
        void (*destroy)(void *) noexcept;

        /// Creates a new object at given memory location by calling the default
        /// constructor.
        void (*default_construct)(void *);

        /// Creates a new object at given memory location by calling the copy
        /// constructor.
        void (*copy_construct)(void *, const void *);

        /// Applies an object to a binary serializer.
        error_code<sec> (*save_binary)(nil::actor::binary_serializer &, const void *);

        /// Applies an object to a binary deserializer.
        error_code<sec> (*load_binary)(nil::actor::binary_deserializer &, void *);

        /// Applies an object to a generic serializer.
        nil::actor::error (*save)(nil::actor::serializer &, const void *);

        /// Applies an object to a generic deserializer.
        nil::actor::error (*load)(nil::actor::deserializer &, void *);

        /// Appends a string representation of an object to a buffer.
        void (*stringify)(std::string &, const void *);
    };

    /// Convenience function for calling `meta.save(sink, obj)`.
    BOOST_SYMBOL_VISIBLE nil::actor::error save(const meta_object &meta, nil::actor::serializer &sink, const void *obj);

    /// Convenience function for calling `meta.save_binary(sink, obj)`.
    BOOST_SYMBOL_VISIBLE nil::actor::error_code<sec> save(const meta_object &meta, nil::actor::binary_serializer &sink,
                                                   const void *obj);

    /// Convenience function for calling `meta.load(source, obj)`.
    BOOST_SYMBOL_VISIBLE nil::actor::error load(const meta_object &meta, nil::actor::deserializer &source, void *obj);

    /// Convenience function for calling `meta.load_binary(source, obj)`.
    BOOST_SYMBOL_VISIBLE nil::actor::error_code<sec> load(const meta_object &meta, nil::actor::binary_deserializer &source,
                                                   void *obj);

    /// Returns the global storage for all meta objects. The ::type_id of an object
    /// is the index for accessing the corresonding meta object.
    BOOST_SYMBOL_VISIBLE span<const meta_object> global_meta_objects();

    /// Returns the global meta object for given type ID.
    BOOST_SYMBOL_VISIBLE const meta_object *global_meta_object(type_id_t id);

    /// Clears the array for storing global meta objects.
    /// @warning intended for unit testing only!
    BOOST_SYMBOL_VISIBLE void clear_global_meta_objects();

    /// Resizes and returns the global storage for all meta objects. Existing
    /// entries are copied to the new memory region. The new size *must* grow the
    /// array.
    /// @warning calling this after constructing any ::spawner is unsafe and
    ///          causes undefined behavior.
    BOOST_SYMBOL_VISIBLE span<meta_object> resize_global_meta_objects(size_t size);

    /// Sets the meta objects in range `[first_id, first_id + xs.size)` to `xs`.
    /// Resizes the global meta object if needed. Aborts the program if the range
    /// already contains meta objects.
    /// @warning calling this after constructing any ::spawner is unsafe and
    ///          causes undefined behavior.
    BOOST_SYMBOL_VISIBLE void set_global_meta_objects(type_id_t first_id, span<const meta_object> xs);

}    // namespace nil::actor::detail