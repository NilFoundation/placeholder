//---------------------------------------------------------------------------//
// Copyright (c) 2011-2020 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#include <nil/actor/type_id_list.hpp>

#include <nil/actor/detail/meta_object.hpp>

namespace nil {
    namespace actor {

        std::string to_string(type_id_list xs) {
            if (!xs || xs.size() == 0)
                return "[]";
            std::string result;
            result += '[';
            result += detail::global_meta_object(xs[0])->type_name;
            for (size_t index = 1; index < xs.size(); ++index) {
                result += ", ";
                result += detail::global_meta_object(xs[index])->type_name;
            }
            result += ']';
            return result;
        }

    }    // namespace actor
}    // namespace nil
