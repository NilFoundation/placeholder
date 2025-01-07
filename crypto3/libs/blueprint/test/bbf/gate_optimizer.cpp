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

// This test checks how the gate optizimer reduces the number of selectors by shifing constraints by +-1 and re-using another
// selector.
BOOST_AUTO_TEST_CASE(blueprint_plonk_bbf_gates_optimizer_shifting_test) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    using integral_type = typename field_type::integral_type;
    using value_type = typename field_type::value_type;

    using assignment_description_type = nil::crypto3::zk::snark::plonk_table_description<field_type>;
    using constraint_type = zk::snark::plonk_constraint<field_type>;
    using context_type = bbf::context<field_type, bbf::GenerationStage::CONSTRAINTS>;

    // Create just 1 of each column type, and 0 already used rows.
    assignment_description_type desc(1, 1, 1, 1, 0, 0);

    // Create a context that can use all 6 rows.
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

// This test checks how the gate optizimer groups selectors used in lookups if they don't intersect.
BOOST_AUTO_TEST_CASE(blueprint_plonk_bbf_gates_optimizer_lookup_selector_grouping_test) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    using integral_type = typename field_type::integral_type;
    using value_type = typename field_type::value_type;

    using assignment_description_type = nil::crypto3::zk::snark::plonk_table_description<field_type>;
    using constraint_type = zk::snark::plonk_constraint<field_type>;
    using context_type = bbf::context<field_type, bbf::GenerationStage::CONSTRAINTS>;
    using lookup_constraint_type = typename context_type::lookup_constraint_type;
    using lookup_input_constraints_type = typename context_type::lookup_input_constraints_type;

    // Create 3 witness columns, and just 1 of each other column type, and 0 already used rows.
    assignment_description_type desc(3, 1, 1, 1, 0, 0);

    // Create a context that can use all 6 rows.
    context_type c(desc, 16);
    constraint_type X, Y, Z;
    c.allocate(X, 0, 0, bbf::column_type::witness);
    c.allocate(Y, 1, 0, bbf::column_type::witness);
    c.allocate(Z, 2, 0, bbf::column_type::witness);
    
    auto c1 = c.relativize(std::vector<constraint_type>({X * X, Y * Y}), 0);
    auto c2 = c.relativize(std::vector<constraint_type>({Z * Z}), 0);
    auto c3 = c.relativize(std::vector<constraint_type>({(X - 1) * (X - 1), (Y - 1) * (Y - 1)}), 0);

    // We don't actually need to create the "Squares table" lookup table for this test, we can just create the
    // lookups and optimize them.
    c.relative_lookup(c1, "Squares Table", 0, 5);
    c.relative_lookup(c2, "Squares Table", 2, 8);
    c.relative_lookup(c3, "Squares Table", 6, 9);

    bbf::gates_optimizer<field_type> optimizer(std::move(c));
    bbf::optimized_gates<field_type> gates = optimizer.optimize_gates();

    // Lookups 1 and 3 will be grouped, and the 2nd will stay as it is.
    BOOST_CHECK_EQUAL(gates.lookup_constraints.size(), 1);
    // We have a group lookup to a single table.
    BOOST_CHECK_EQUAL(gates.grouped_lookups.size(), 1);
    // And we have just 1 group inside.
    BOOST_CHECK_EQUAL(gates.grouped_lookups["Squares Table"].size(), 1);
    // The only group must have 2 selectors inside.
    BOOST_CHECK_EQUAL(gates.grouped_lookups["Squares Table"].begin()->second.size(), 2);

    // Check that 2-nd constraint did not get grouped.
    bbf::row_selector<> expected_selector_for_2nd(16);
    expected_selector_for_2nd.set_interval(2, 8);

    size_t selector_id_for_2nd_constraint = gates.lookup_constraints.begin()->first;
    BOOST_CHECK_EQUAL(gates.selectors_[expected_selector_for_2nd], selector_id_for_2nd_constraint);
    BOOST_CHECK(
        gates.lookup_constraints.begin()->second ==
        std::vector<lookup_constraint_type>({
            std::make_pair("Squares Table", c2)
        })
    );

    // Check the grouped selectors.
    bbf::row_selector<> expected_selector_for_1st(16);
    expected_selector_for_1st.set_interval(0 ,5);
    bbf::row_selector<> expected_selector_for_3rd(16);
    expected_selector_for_3rd.set_interval(6, 9);

    for (auto [selector_id, li] : gates.grouped_lookups["Squares Table"].begin()->second) {
        if (selector_id == gates.selectors_[expected_selector_for_1st]) {
            BOOST_CHECK(li == c1);
        } else if (selector_id == gates.selectors_[expected_selector_for_3rd]) {
            BOOST_CHECK(li == c3);
        } else {
            BOOST_CHECK(false);
        }
    }
}

// This test checks how the gate optizimer groups selectors used in lookups if they don't intersect.
BOOST_AUTO_TEST_CASE(blueprint_plonk_bbf_gates_optimizer_lookup_selector_larger_grouping_test) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    using integral_type = typename field_type::integral_type;
    using value_type = typename field_type::value_type;

    using assignment_description_type = nil::crypto3::zk::snark::plonk_table_description<field_type>;
    using constraint_type = zk::snark::plonk_constraint<field_type>;
    using context_type = bbf::context<field_type, bbf::GenerationStage::CONSTRAINTS>;
    using lookup_constraint_type = typename context_type::lookup_constraint_type;
    using lookup_input_constraints_type = typename context_type::lookup_input_constraints_type;

    // Create 3 witness columns, and just 1 of each other column type, and 0 already used rows.
    assignment_description_type desc(3, 1, 1, 1, 0, 0);

    // Create a context that can use all 6 rows.
    context_type c(desc, 16);
    constraint_type X, Y, Z;
    c.allocate(X, 0, 0, bbf::column_type::witness);
    c.allocate(Y, 1, 0, bbf::column_type::witness);
    c.allocate(Z, 2, 0, bbf::column_type::witness);
    
    auto c1 = c.relativize(std::vector<constraint_type>({X * X, Y * Y}), 0);
    auto c2 = c.relativize(std::vector<constraint_type>({Z * Z}), 0);
    auto c3 = c.relativize(std::vector<constraint_type>({(X - 1) * (X - 1), (Y - 1) * (Y - 1)}), 0);
    auto c4 = c.relativize(std::vector<constraint_type>({(X - 2) * (X - 2), (Y - 2) * (Y - 2)}), 0);
    auto c5 = c.relativize(std::vector<constraint_type>({(X - 3) * (X - 2), (Y - 3) * (Y - 3)}), 0);
    auto c6 = c.relativize(std::vector<constraint_type>({(X - 4) * (X - 4), (Y - 4) * (Y - 4)}), 0);
    auto c7 = c.relativize(std::vector<constraint_type>({(X - 5) * (X - 5), (Y - 5) * (Y - 5)}), 0);

    // We want a wheel graph, a circle with a node in the middle. selector for 'c1' will intersect every other constraint,
    // while each other one will only intersect with the one to the left and right of it.
    // We don't actually need to create the "Squares table" lookup table for this test, we can just create the
    // lookups and optimize them.
    c.relative_lookup(c1, "Squares Table", 0, 14);
    c.relative_lookup(c2, "Squares Table", 0, 2);
    c.relative_lookup(c3, "Squares Table", 2, 4);
    c.relative_lookup(c4, "Squares Table", 4, 6);
    c.relative_lookup(c5, "Squares Table", 6, 8);
    c.relative_lookup(c6, "Squares Table", 8, 10);

    c.relative_lookup(c7, "Squares Table", 10, 12);
    c.relative_lookup(c7, "Squares Table", 0);

    bbf::gates_optimizer<field_type> optimizer(std::move(c));
    bbf::optimized_gates<field_type> gates = optimizer.optimize_gates();

    // Lookups 'c1' will stay single.
    BOOST_CHECK_EQUAL(gates.lookup_constraints.size(), 1);
    // We have a group lookup to a single table.
    BOOST_CHECK_EQUAL(gates.grouped_lookups.size(), 1);

    // And we have just 2 groups inside, [c2, c4, c6] and [c3, c5, c7].
    BOOST_CHECK_EQUAL(gates.grouped_lookups["Squares Table"].size(), 2);
}

BOOST_AUTO_TEST_SUITE_END()