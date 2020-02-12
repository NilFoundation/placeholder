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

#include <nil/actor/type_erased_value.hpp>

namespace nil {
    namespace actor {

        type_erased_value::~type_erased_value() {
            // nop
        }

        bool type_erased_value::matches(uint16_t nr, const std::type_info *ptr) const {
            auto tp = type();
            if (tp.first != nr)
                return false;
            if (nr == 0)
                return ptr != nullptr ? *tp.second == *ptr : false;
            return true;
        }

    }    // namespace actor
}    // namespace nil
