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

#include <nil/actor/fwd.hpp>
#include <nil/actor/ref_counted.hpp>
#include <nil/actor/resumable.hpp>

namespace nil::actor::detail {

    class BOOST_SYMBOL_VISIBLE abstract_worker : public ref_counted, public resumable {
    public:
        // -- friends ----------------------------------------------------------------

        friend abstract_worker_hub;

        // -- constructors, destructors, and assignment operators --------------------

        abstract_worker();

        ~abstract_worker() override;

        // -- implementation of resumable --------------------------------------------

        subtype_t subtype() const override;

        void intrusive_ptr_add_ref_impl() override;

        void intrusive_ptr_release_impl() override;

    private:
        // -- member variables -------------------------------------------------------

        /// Points to the next worker in the hub.
        std::atomic<abstract_worker *> next_;
    };
}    // namespace nil::actor::detail
