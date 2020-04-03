//---------------------------------------------------------------------------//
// Copyright (c) 2011-2020 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <utility>

#include <nil/actor/detail/make_meta_object.hpp>
#include <nil/actor/detail/meta_object.hpp>
#include <nil/actor/span.hpp>
#include <nil/actor/type_id.hpp>

namespace nil::actor::detail {

    template<uint16_t First, uint16_t Second>
    struct type_id_pair {};

    template<class Range, uint16_t... Is>
    struct type_id_sequence_helper;

    template<uint16_t End, uint16_t... Is>
    struct type_id_sequence_helper<type_id_pair<End, End>, Is...> {
        using type = std::integer_sequence<uint16_t, Is...>;
    };

    template<uint16_t Begin, uint16_t End, uint16_t... Is>
    struct type_id_sequence_helper<type_id_pair<Begin, End>, Is...> {
        using type = typename type_id_sequence_helper<type_id_pair<Begin + 1, End>, Is..., Begin>::type;
    };

    template<class Range>
    using make_type_id_sequence = typename type_id_sequence_helper<type_id_pair<Range::begin, Range::end>>::type;

}    // namespace nil::actor::detail

namespace nil {
    namespace actor {

        /// @warning calling this after constructing any ::spawner is unsafe and
        ///          causes undefined behavior.
        template<class ProjectIds, uint16_t... Is>
        void init_global_meta_objects_impl(std::integer_sequence<uint16_t, Is...>) {
            static_assert(sizeof...(Is) > 0);
            detail::meta_object src[] = {
                detail::make_meta_object<type_by_id_t<Is>>(type_name_by_id_v<Is>)...,
            };
            detail::set_global_meta_objects(ProjectIds::begin, make_span(src));
        }

        /// Initializes the global meta object table with all types in `ProjectIds`.
        /// @warning calling this after constructing any ::spawner is unsafe and
        ///          causes undefined behavior.
        template<class ProjectIds>
        void init_global_meta_objects() {
            detail::make_type_id_sequence<ProjectIds> seq;
            init_global_meta_objects_impl<ProjectIds>(seq);
        }

    }    // namespace actor
}    // namespace nil

namespace nil::actor::core {

    /// Initializes the meta objects of the core module.
    BOOST_SYMBOL_VISIBLE void init_global_meta_objects();

}    // namespace nil::actor::core