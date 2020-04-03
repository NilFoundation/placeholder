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

#include <boost/config.hpp>

namespace nil::actor {

    /// This base enables derived classes to enforce a different
    /// allocation strategy than new/delete by providing a virtual
    /// protected `request_deletion()` function and non-public destructor.
    class BOOST_SYMBOL_VISIBLE memory_managed {
    public:
        /// Default implementations calls `delete this, but can
        /// be overridden in case deletion depends on some condition or
        /// the class doesn't use default new/delete.
        /// @param decremented_rc Indicates whether the caller did reduce the
        ///                       reference of this object before calling this member
        ///                       function. This information is important when
        ///                       implementing a type with support for weak pointers.
        virtual void request_deletion(bool decremented_rc) const noexcept;

    protected:
        virtual ~memory_managed();
    };
}    // namespace nil::actor
