////---------------------------------------------------------------------------//
//// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//// Copyright (c) 2021-2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
////
//// MIT License
////
//// Permission is hereby granted, free of charge, to any person obtaining a copy
//// of this software and associated documentation files (the "Software"), to deal
//// in the Software without restriction, including without limitation the rights
//// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//// copies of the Software, and to permit persons to whom the Software is
//// furnished to do so, subject to the following conditions:
////
//// The above copyright notice and this permission notice shall be included in all
//// copies or substantial portions of the Software.
////
//// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//// SOFTWARE.
////---------------------------------------------------------------------------//

#include <nil/actor/testing/test_case.hh>
#include <nil/actor/core/memory.hh>
#include <nil/actor/core/smp.hh>
#include <nil/actor/core/temporary_buffer.hh>
#include <nil/actor/detail/memory_diagnostics.hh>

#include <vector>
#include <future>
#include <iostream>

#include <cstdlib>

using namespace nil::actor;

ACTOR_TEST_CASE(merkletree_actor_test) {
    BOOST_ASSERT(1 == 1);
    return make_ready_future<>();
}