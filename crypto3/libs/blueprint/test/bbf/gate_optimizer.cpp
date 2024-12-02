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

#define BOOST_TEST_MODULE blueprint_plonk_bbf_gates_optimizier_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>

#include <nil/blueprint/bbf/row_selector.hpp>
#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/bbf/enums.hpp>
#include <nil/blueprint/bbf/gate_optimizer.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

using namespace nil::crypto3;
using namespace nil::blueprint;

BOOST_AUTO_TEST_SUITE(blueprint_bbf_gates_optimizer_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_bbf_gates_optimizer_test) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    using integral_type = typename field_type::integral_type;
    using value_type = typename field_type::value_type;

    using assignment_description_type = nil::crypto3::zk::snark::plonk_table_description<field_type>;
	using constraint_type = zk::snark::plonk_constraint<field_type>;
    using context_type = bbf::context<field_type, bbf::GenerationStage::CONSTRAINTS>;

	// Create just 1 of each column type, and 0 already used rows.
	assignment_description_type desc(1, 1, 1, 1, 0, 0);

	// Create a context that can use all 5 rows.
	context_type c(desc, 6);
	
	constraint_type X1, X2, X3, X4, X5, X6;
	c.allocate(X1, 0, 0, bbf::column_type::witness);
	c.constrain(X1*(1-X1), "Left Constraint");

	// Same thing on row 2.
	c.allocate(X2, 0, 3, bbf::column_type::witness);
	c.constrain(X2*(1-X2), "Left Constraint 2");

	c.allocate(X3, 0, 1, bbf::column_type::witness);
	c.constrain(X3*(2-X3), "Middle constraint 1");

	c.allocate(X4, 0, 4, bbf::column_type::witness);
	c.constrain(X4*(2-X4), "Middle constraint 2");

	c.allocate(X5, 0, 2, bbf::column_type::witness);
	c.constrain(X5*(3-X5), "Right constraint 1");

	c.allocate(X6, 0, 5, bbf::column_type::witness);
	c.constrain(X6*(3-X6), "Right constraint 2");

	bbf::gates_optimizer<field_type> optimizer(std::move(c));
	bbf::optimized_gates<field_type> gates = optimizer.optimize_gates();

	// We must have just 1 selector here, since these constraints can be shifted to match the same selector.
	BOOST_CHECK_EQUAL(gates.selectors_.size(), 1);

	bbf::row_selector<> expected(8);
	expected.set_row(1);
	expected.set_row(4);

	// This must be selector [1,4], since it's in the middle and the other 2 can be switched to that one.
	BOOST_CHECK_EQUAL(gates.selectors_.begin()->first, expected);
}

BOOST_AUTO_TEST_SUITE_END()
