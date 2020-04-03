//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#include <iterator>

#include <nil/actor/detail/behavior_stack.hpp>
#include <nil/actor/local_actor.hpp>
#include <nil/actor/none.hpp>

namespace nil::actor::detail {

    void behavior_stack::pop_back() {
        ACTOR_ASSERT(!elements_.empty());
        erased_elements_.push_back(std::move(elements_.back()));
        elements_.pop_back();
    }

    void behavior_stack::clear() {
        if (!elements_.empty()) {
            if (erased_elements_.empty()) {
                elements_.swap(erased_elements_);
            } else {
                std::move(elements_.begin(), elements_.end(), std::back_inserter(erased_elements_));
                elements_.clear();
            }
        }
    }

}    // namespace nil::actor::detail