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

namespace nil::actor::detail {

    template<template<class, typename> class Tpl, typename Arg1>
    struct tbind {
        template<class Arg2>
        struct type {
            static constexpr bool value = Tpl<Arg1, Arg2>::value;
        };
    };

}    // namespace nil::actor::detail