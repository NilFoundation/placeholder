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

#include <nil/actor/replies_to.hpp>
#include <nil/actor/string_algorithms.hpp>

namespace nil {
    namespace actor {

        std::string replies_to_type_name(size_t input_size,
                                         const std::string *input,
                                         size_t output_opt1_size,
                                         const std::string *output_opt1) {
            string_view glue = ",";
            std::string result;
            // 'void' is not an announced type, hence we check whether uniform_typeid
            // did return a valid pointer to identify 'void' (this has the
            // possibility of false positives, but those will be catched anyways)
            result = "nil::actor::replies_to<";
            result += join(input, input + input_size, glue);
            result += ">::with<";
            result += join(output_opt1, output_opt1 + output_opt1_size, glue);
            result += ">";
            return result;
        }

    }    // namespace actor
}    // namespace nil
