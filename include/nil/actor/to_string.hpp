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

#include <string>

#include <nil/actor/deep_to_string.hpp>
#include <nil/actor/detail/stringification_inspector.hpp>
#include <nil/actor/detail/type_traits.hpp>
#include <nil/actor/error.hpp>

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
