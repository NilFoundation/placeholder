//---------------------------------------------------------------------------//
// Copyright (c) 2011-2019 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#pragma once

#include <nil/actor/detail/message_data.hpp>
#include <nil/actor/detail/offset_at.hpp>
#include <nil/actor/detail/type_list.hpp>
#include <nil/actor/message.hpp>

namespace nil::actor {

    template<class... Ts>
    class typed_message_view {
    public:
        typed_message_view() noexcept : ptr_(nullptr) {
            // nop
        }

        explicit typed_message_view(message &msg) : ptr_(&msg.data()) {
            // nop
        }

        typed_message_view(const typed_message_view &) noexcept = default;

        typed_message_view &operator=(const typed_message_view &) noexcept = default;

        detail::message_data *operator->() noexcept {
            return ptr_;
        }

        explicit operator bool() const noexcept {
            return ptr_ != nullptr;
        }

    private:
        detail::message_data *ptr_;
    };

    template<size_t Index, class... Ts>
    auto &get(typed_message_view<Ts...> x) {
        static_assert(Index < sizeof...(Ts));
        using type = nil::actor::detail::tl_at_t<nil::actor::detail::type_list<Ts...>, Index>;
        return *reinterpret_cast<type *>(x->storage() + detail::offset_at<Index, Ts...>);
    }

    template<class... Ts>
    auto make_typed_message_view(message &msg) {
        if (msg.types() == make_type_id_list<Ts...>())
            return typed_message_view<Ts...> {msg};
        return typed_message_view<Ts...> {};
    }

}    // namespace nil::actor
