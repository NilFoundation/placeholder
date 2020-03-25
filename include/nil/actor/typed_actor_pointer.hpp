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

#include <nil/actor/typed_actor_view.hpp>

#include <nil/actor/detail/type_list.hpp>

namespace nil {
    namespace actor {

        template<class... Sigs>
        class typed_actor_pointer {
        public:
            /// Stores the template parameter pack.
            using signatures = detail::type_list<Sigs...>;

            template<class Supertype>
            typed_actor_pointer(Supertype *selfptr) : view_(selfptr) {
                using namespace nil::actor::detail;
                static_assert(tl_subset_of<type_list<Sigs...>, typename Supertype::signatures>::value,
                              "cannot create a pointer view to an unrelated actor type");
            }

            typed_actor_pointer(std::nullptr_t) : view_(nullptr) {
                // nop
            }

            typed_actor_view<Sigs...> *operator->() {
                return &view_;
            }

            const typed_actor_view<Sigs...> *operator->() const {
                return &view_;
            }

            explicit operator bool() const {
                return static_cast<bool>(view_.internal_ptr());
            }

            /// @private
            actor_control_block *get() const {
                return view_.ctrl();
            }

            /// @private
            scheduled_actor *internal_ptr() const {
                return view_.internal_ptr();
            }

            template<class Supertype>
            typed_actor_pointer &operator=(Supertype *ptr) {
                using namespace nil::actor::detail;
                static_assert(tl_subset_of<type_list<Sigs...>, typename Supertype::signatures>::value,
                              "cannot assign pointer of unrelated actor type");
                view_ = ptr;
                return *this;
            }

        private:
            typed_actor_view<Sigs...> view_;
        };

    }    // namespace actor
}    // namespace nil
