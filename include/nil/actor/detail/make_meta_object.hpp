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

#include <algorithm>
#include <cstddef>

#include <nil/actor/binary_deserializer.hpp>
#include <nil/actor/binary_serializer.hpp>
#include <nil/actor/byte.hpp>
#include <nil/actor/deserializer.hpp>
#include <nil/actor/detail/meta_object.hpp>
#include <nil/actor/detail/padded_size.hpp>
#include <nil/actor/detail/stringification_inspector.hpp>
#include <nil/actor/error.hpp>
#include <nil/actor/serializer.hpp>

namespace nil::actor::detail::default_function {

    template<class T>
    void destroy(void *ptr) noexcept {
        reinterpret_cast<T *>(ptr)->~T();
    }

    template<class T>
    void default_construct(void *ptr) {
        new (ptr) T();
    }

    template<class T>
    void copy_construct(void *ptr, const void *src) {
        new (ptr) T(*reinterpret_cast<const T *>(src));
    }

    template<class T>
    error_code<sec> save_binary(nil::actor::binary_serializer &sink, const void *ptr) {
        return sink(*reinterpret_cast<const T *>(ptr));
    }

    template<class T>
    error_code<sec> load_binary(nil::actor::binary_deserializer &source, void *ptr) {
        return source(*reinterpret_cast<T *>(ptr));
    }

    template<class T>
    nil::actor::error save(nil::actor::serializer &sink, const void *ptr) {
        return sink(*reinterpret_cast<const T *>(ptr));
    }

    template<class T>
    nil::actor::error load(nil::actor::deserializer &source, void *ptr) {
        return source(*reinterpret_cast<T *>(ptr));
    }

    template<class T>
    void stringify(std::string &buf, const void *ptr) {
        stringification_inspector f {buf};
        f(*reinterpret_cast<const T *>(ptr));
    }

}    // namespace nil::actor::detail::default_function

namespace nil::actor::detail {

    template<class T>
    meta_object make_meta_object(const char *type_name) {
        return {
            type_name,
            padded_size_v<T>,
            default_function::destroy<T>,
            default_function::default_construct<T>,
            default_function::copy_construct<T>,
            default_function::save_binary<T>,
            default_function::load_binary<T>,
            default_function::save<T>,
            default_function::load<T>,
            default_function::stringify<T>,
        };
    }
}    // namespace nil::actor::detail