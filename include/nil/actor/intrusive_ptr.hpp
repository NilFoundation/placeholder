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

#include <boost/smart_ptr/intrusive_ptr.hpp>

#include <nil/crypto3/codec/algorithm/encode.hpp>
#include <nil/crypto3/codec/hex.hpp>

#include <nil/actor/detail/comparable.hpp>
#include <nil/actor/detail/type_traits.hpp>
#include <nil/actor/fwd.hpp>

namespace nil {
    namespace actor {

        template<typename T>
        using intrusive_ptr = boost::intrusive_ptr<T>;

        template<typename T>
        struct has_weak_ptr_semantics {
            constexpr static const bool value = false;
        };

        template<typename T>
        struct has_weak_ptr_semantics<intrusive_ptr<T>> {
            constexpr static const bool value = false;
        };

        template<class T>
        std::string to_string(const intrusive_ptr<T> &x) {
            using namespace nil::crypto3;

            auto v = reinterpret_cast<uintptr_t>(x.get());
            auto ptr = reinterpret_cast<uint8_t *>(&v);
            return encode<codec::hex<>>(ptr, ptr + sizeof(v));
        }
    }    // namespace actor
}    // namespace nil
