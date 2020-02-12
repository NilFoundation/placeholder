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

namespace nil {
    namespace actor {

        /// This base enables derived classes to enforce a different
        /// allocation strategy than new/delete by providing a virtual
        /// protected `request_deletion()` function and non-public destructor.
        class memory_managed {
        public:
            /// Default implementations calls `delete this, but can
            /// be overriden in case deletion depends on some condition or
            /// the class doesn't use default new/delete.
            /// @param decremented_rc Indicates whether the caller did reduce the
            ///                       reference of this object before calling this member
            ///                       function. This information is important when
            ///                       implementing a type with support for weak pointers.
            virtual void request_deletion(bool decremented_rc) const noexcept;

        protected:
            virtual ~memory_managed();
        };

    }    // namespace actor
}    // namespace nil
