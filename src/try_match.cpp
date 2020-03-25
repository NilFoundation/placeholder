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

#include <nil/actor/detail/try_match.hpp>

#include <nil/actor/type_erased_tuple.hpp>

namespace nil {
    namespace actor {
        namespace detail {

            using pattern_iterator = const meta_element *;

            bool match_element(const meta_element &me, const type_erased_tuple &xs, size_t pos) {
                ACTOR_ASSERT(me.typenr != 0 || me.type != nullptr);
                return xs.matches(pos, me.typenr, me.type);
            }

            bool match_atom_constant(const meta_element &me, const type_erased_tuple &xs, size_t pos) {
                ACTOR_ASSERT(me.typenr == type_nr<atom_value>::value);
                if (!xs.matches(pos, type_nr<atom_value>::value, nullptr))
                    return false;
                auto ptr = xs.get(pos);
                return me.v == *reinterpret_cast<const atom_value *>(ptr);
            }

            bool try_match(const type_erased_tuple &xs, pattern_iterator iter, size_t ps) {
                if (xs.size() != ps)
                    return false;
                for (size_t i = 0; i < ps; ++i, ++iter)
                    // inspect current element
                    if (!iter->fun(*iter, xs, i))
                        // type mismatch
                        return false;
                return true;
            }

        }    // namespace detail
    }        // namespace actor
}    // namespace nil
