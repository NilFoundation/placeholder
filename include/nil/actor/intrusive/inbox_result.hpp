//---------------------------------------------------------------------------//
// Copyright (c) 2011-2017 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#pragma once

#include <string>

#include <boost/config.hpp>

namespace nil::actor::intrusive {

    /// Communicates the state of a LIFO or FIFO inbox after pushing to it.
    enum class inbox_result {
        /// Indicates that the enqueue operation succeeded and
        /// the reader is ready to receive the data.
        success,

        /// Indicates that the enqueue operation succeeded and
        /// the reader is currently blocked, i.e., needs to be re-scheduled.
        unblocked_reader,

        /// Indicates that the enqueue operation failed because the
        /// queue has been closed by the reader.
        queue_closed,
    };

    BOOST_SYMBOL_VISIBLE std::string to_string(inbox_result);

}    // namespace nil::actor::intrusive