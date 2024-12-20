//---------------------------------------------------------------------------//
// Copyright (c) 2024 Martun Karapetyan <martun@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE hash_type_traits_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>
#include <boost/container/vector.hpp>

#include <nil/crypto3/algebra/type_traits.hpp>
#include <nil/crypto3/hash/keccak.hpp>

using namespace nil::crypto3::algebra;

BOOST_AUTO_TEST_SUITE(hash_type_traits_manual_tests)

BOOST_AUTO_TEST_CASE(test_hash_traits) {
    BOOST_ASSERT(nil::crypto3::detail::has_digest_type<nil::crypto3::hashes::keccak_1600<256>>::value);
    BOOST_ASSERT(nil::crypto3::detail::has_digest_bits<nil::crypto3::hashes::keccak_1600<256>>::value);
    BOOST_ASSERT(nil::crypto3::detail::is_hash<nil::crypto3::hashes::keccak_1600<256>>::value);
}

BOOST_AUTO_TEST_SUITE_END()
