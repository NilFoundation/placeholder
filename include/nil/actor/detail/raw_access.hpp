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

#include <nil/actor/abstract_actor.hpp>
#include <nil/actor/abstract_channel.hpp>
#include <nil/actor/abstract_group.hpp>
#include <nil/actor/actor.hpp>
#include <nil/actor/actor_addr.hpp>
#include <nil/actor/channel.hpp>
#include <nil/actor/group.hpp>

namespace nil::actor::detail {

    class raw_access {
    public:
        template<class ActorHandle>
        static abstract_actor *get(const ActorHandle &hdl) {
            return hdl.ptr_.get();
        }

        static abstract_channel *get(const channel &hdl) {
            return hdl.ptr_.get();
        }

        static abstract_group *get(const group &hdl) {
            return hdl.ptr_.get();
        }

        static actor unsafe_cast(abstract_actor *ptr) {
            return {ptr};
        }

        static actor unsafe_cast(const actor_addr &hdl) {
            return {get(hdl)};
        }

        static actor unsafe_cast(const abstract_actor_ptr &ptr) {
            return {ptr.get()};
        }

        template<class T>
        static void unsafe_assign(T &lhs, const actor &rhs) {
            lhs = T {get(rhs)};
        }

        template<class T>
        static void unsafe_assign(T &lhs, const abstract_actor_ptr &ptr) {
            lhs = T {ptr.get()};
        }
    };

}    // namespace nil::actor::detail