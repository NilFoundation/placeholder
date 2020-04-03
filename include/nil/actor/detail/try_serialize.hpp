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

    template<class Processor, class T>
    auto try_serialize(Processor &proc, T *x) -> decltype(proc & *x) {
        proc &*x;
    }

    template<class Processor>
    void try_serialize(Processor &, void *) {
        // nop
    }

}    // namespace nil::actor::detail