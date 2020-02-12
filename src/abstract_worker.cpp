//---------------------------------------------------------------------------//
// Copyright (c) 2011-2019 Dominik Charousset
// Copyright (c) 2019 Nil Foundation AG
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE and LICENSE_ALTERNATIVE.
//---------------------------------------------------------------------------//

#include <nil/actor/detail/abstract_worker.hpp>

namespace nil {
    namespace actor {
        namespace detail {

            // -- constructors, destructors, and assignment operators ----------------------

            abstract_worker::abstract_worker() : next_(nullptr) {
                // nop
            }

            abstract_worker::~abstract_worker() {
                // nop
            }

            // -- implementation of resumable ----------------------------------------------

            resumable::subtype_t abstract_worker::subtype() const {
                return resumable::function_object;
            }

            void abstract_worker::intrusive_ptr_add_ref_impl() {
                ref();
            }

            void abstract_worker::intrusive_ptr_release_impl() {
                deref();
            }

        }    // namespace detail
    }        // namespace actor
}    // namespace nil
