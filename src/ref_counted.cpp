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

#include <nil/actor/ref_counted.hpp>

namespace nil {
    namespace actor {

        ref_counted::~ref_counted() {
            // nop
        }

        ref_counted::ref_counted() : rc_(1) {
            // nop
        }

        ref_counted::ref_counted(const ref_counted &) : rc_(1) {
            // nop; don't copy reference count
        }

        ref_counted &ref_counted::operator=(const ref_counted &) {
            // nop; intentionally don't copy reference count
            return *this;
        }

        void ref_counted::deref() const noexcept {
            if (unique()) {
                request_deletion(false);
                return;
            }
            if (rc_.fetch_sub(1, std::memory_order_acq_rel) == 1) {
                request_deletion(true);
            }
        }

    }    // namespace actor
}    // namespace nil
