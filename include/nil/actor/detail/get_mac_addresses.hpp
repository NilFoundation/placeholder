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

#include <string>
#include <utility>
#include <vector>

#include <boost/config.hpp>

namespace nil::actor::detail {

    using iface_info = std::pair<std::string /* interface name */, std::string /* interface address */>;

    BOOST_SYMBOL_VISIBLE std::vector<iface_info> get_mac_addresses();

}    // namespace nil::actor::detail