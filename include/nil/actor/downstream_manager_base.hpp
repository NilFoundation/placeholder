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

#pragma once

#include <cstddef>
#include <memory>

#include <nil/actor/downstream_manager.hpp>
#include <nil/actor/outbound_path.hpp>

#include <nil/actor/detail/unordered_flat_map.hpp>

namespace nil {
    namespace actor {

        /// The default downstream manager base stores outbound paths in an unordered
        /// map. It always takes ownership of the pahts by using unique pointers.
        class downstream_manager_base : public downstream_manager {
        public:
            // -- member types -----------------------------------------------------------

            /// Base type.
            using super = downstream_manager;

            /// Maps slots to paths.
            using map_type = detail::unordered_flat_map<stream_slot, unique_path_ptr>;

            // -- constructors, destructors, and assignment operators --------------------

            explicit downstream_manager_base(stream_manager *parent);

            ~downstream_manager_base() override;

            // -- properties -------------------------------------------------------------

            inline const map_type &paths() const {
                return paths_;
            }

            inline map_type &paths() {
                return paths_;
            }

            // -- path management --------------------------------------------------------

            size_t num_paths() const noexcept override;

            bool remove_path(stream_slot slots, error reason, bool silent) noexcept override;

            path_ptr path(stream_slot slots) noexcept override;

            void clear_paths() override;

        protected:
            bool insert_path(unique_path_ptr ptr) override;

            void for_each_path_impl(path_visitor &f) override;

            bool check_paths_impl(path_algorithm algo, path_predicate &pred) const noexcept override;

            // -- member variables -------------------------------------------------------

            map_type paths_;
        };

    }    // namespace actor
}    // namespace nil
