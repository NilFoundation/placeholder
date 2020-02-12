//---------------------------------------------------------------------------//
// Copyright (c) 2011-2019 Dominik Charousset
// Copyright (c) 2019 Nil Foundation AG
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE and LICENSE_ALTERNATIVE.
//---------------------------------------------------------------------------//

#include <nil/actor/rtti_pair.hpp>

namespace nil {
    namespace actor {

        std::string to_string(rtti_pair x) {
            std::string result = "(";
            result += std::to_string(x.first);
            result += ", ";
            result += x.second != nullptr ? x.second->name() : "<null>";
            result += ")";
            return result;
        }

    }    // namespace actor
}    // namespace nil
