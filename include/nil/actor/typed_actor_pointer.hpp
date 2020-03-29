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

#include <nil/actor/detail/type_list.hpp>
#include <nil/actor/detail/type_traits.hpp>
#include <nil/actor/typed_actor_view.hpp>

namespace nil {
    namespace actor {

        template<class... Sigs>
        class typed_actor_pointer : public typed_actor_view_base {
        public:
            /// Stores the template parameter pack.
            using signatures = detail::type_list<Sigs...>;

            typed_actor_pointer() : view_(nullptr) {
                // nop
            }

            template<class Supertype,
                     class = detail::enable_if_t<    //
                         detail::tl_subset_of<detail::type_list<Sigs...>, typename Supertype::signatures>::value>>
            typed_actor_pointer(Supertype *selfptr) : view_(selfptr) {
                // nop
            }

            template<class... OtherSigs,
                     class = detail::enable_if_t<    //
                         detail::tl_subset_of<detail::type_list<Sigs...>, detail::type_list<OtherSigs...>>::value>>
            typed_actor_pointer(typed_actor_pointer<OtherSigs...> other) : view_(other.internal_ptr()) {
                // nop
            }

            typed_actor_pointer(const typed_actor_pointer &) = default;

            explicit typed_actor_pointer(std::nullptr_t) : view_(nullptr) {
                // nop
            }

            typed_actor_pointer &operator=(const typed_actor_pointer &) = default;

            template<class Supertype>
            typed_actor_pointer &operator=(Supertype *ptr) {
                using namespace detail;
                static_assert(tl_subset_of<type_list<Sigs...>, typename Supertype::signatures>::value,
                              "cannot assign pointer of unrelated actor type");
                view_.reset(ptr);
                return *this;
            }

            template<class... OtherSigs,
                     class = detail::enable_if_t<    //
                         detail::tl_subset_of<detail::type_list<Sigs...>, detail::type_list<OtherSigs...>>::value>>
            typed_actor_pointer &operator=(typed_actor_pointer<OtherSigs...> other) {
                using namespace detail;
                static_assert(tl_subset_of<type_list<Sigs...>, type_list<OtherSigs...>>::value,
                              "cannot assign pointer of unrelated actor type");
                view_.reset(other.internal_ptr());
                return *this;
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
            scheduled_actor *internal_ptr() const noexcept {
                return view_.internal_ptr();
            }

            operator scheduled_actor *() const noexcept {
                return view_.internal_ptr();
            }

        private:
            typed_actor_view<Sigs...> view_;
        };

    }    // namespace actor
}    // namespace nil
