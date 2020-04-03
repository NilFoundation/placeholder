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
#include <typeinfo>

#include <boost/config.hpp>

namespace nil::actor::detail {

    BOOST_SYMBOL_VISIBLE void prettify_type_name(std::string &class_name);

    BOOST_SYMBOL_VISIBLE void prettify_type_name(std::string &class_name, const char *input_class_name);

    BOOST_SYMBOL_VISIBLE std::string pretty_type_name(const std::type_info &x);

}    // namespace nil::actor::detail