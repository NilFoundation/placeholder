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

#include <string>

#include <nil/actor/error.hpp>
#include <nil/actor/deep_to_string.hpp>

#include <nil/actor/detail/type_traits.hpp>
#include <nil/actor/detail/stringification_inspector.hpp>

namespace nil {
    namespace actor {

        template<class T, class E = typename std::enable_if<
                              detail::is_inspectable<detail::stringification_inspector, T>::value>::type>
        std::string to_string(const T &x) {
            std::string res;
            detail::stringification_inspector f {res};
            inspect(f, const_cast<T &>(x));
            return res;
        }

    }    // namespace actor
}    // namespace nil
