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

#define BOOST_TEST_MODULE blueprint_plonk_bbf_row_selector_test

#include <boost/test/unit_test.hpp>

#include <nil/blueprint/bbf/row_selector.hpp>

using namespace nil::blueprint;

BOOST_AUTO_TEST_SUITE(blueprint_bbf_row_selector_test)

BOOST_AUTO_TEST_CASE(blueprint_plonk_bbf_row_selector_test) {
	size_t max_rows = 10;
	bbf::row_selector<> r(max_rows);
	r.set_row(0);
	r.set_row(2);
	r.set_row(5);
	std::vector<size_t> v(r.begin(), r.end());
	std::vector<size_t> expected = {0, 2, 5};
	BOOST_CHECK_EQUAL_COLLECTIONS(
		v.begin(), v.end(), 
		expected.begin(), expected.end());
}

BOOST_AUTO_TEST_SUITE_END()
