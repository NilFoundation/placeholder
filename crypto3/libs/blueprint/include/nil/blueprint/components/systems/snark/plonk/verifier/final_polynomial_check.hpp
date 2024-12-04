//---------------------------------------------------------------------------//
// Copyright (c) 2024 Dmitrii Tabalin <d.tabalin@nil.foundation>
// Copyright (c) 2024 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#pragma once

#include "nil/blueprint/components/algebra/fields/plonk/addition.hpp"
#include "nil/blueprint/components/algebra/fields/plonk/multiplication.hpp"
#include "nil/blueprint/components/systems/snark/plonk/placeholder/detail/expression_evaluation_component.hpp"
#include <unordered_map>

#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            using detail::expression_evaluation_component;

            template<typename ArithmetizationType>
            class final_polynomial_check;

            // checks that the polynomial defined by power + 1 coefficients has values equal to 2*lambda passed values
            // at 2*lambda points of the form (s, -s)
            // (where one of the points is passed, and the other one is inferred)
            // coefficients passed highest to lowest power
            template<typename BlueprintFieldType>
            class final_polynomial_check<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                : public plonk_component<BlueprintFieldType> {
            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using constraint_type = nil::crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using manifest_type = nil::blueprint::plonk_component_manifest;
                using expression_evaluator_type = plonk_expression_evaluation_component<BlueprintFieldType>;

                std::size_t power;
                std::size_t lambda;

                std::size_t rows_amount;
                static const std::size_t gates_amount = 0;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    gate_manifest_type(std::size_t witness_amount, std::size_t power, std::size_t lambda) {
                        if( power < 8 ) num_gates = 1; else num_gates = 2;
                    }
                    std::uint32_t gates_amount() const override {
                        return num_gates;
                    }
                    std::size_t num_gates;
                };

                static gate_manifest get_gate_manifest(
                        std::size_t witness_amount, std::size_t _power, std::size_t _lambda) {
                    static gate_manifest manifest = gate_manifest_type(witness_amount, _power, _lambda);
                    return manifest;
                }

                static manifest_type get_manifest(std::size_t power, std::size_t labmda) {
                    static manifest_type manifest =
                        manifest_type(std::shared_ptr<manifest_param>(new manifest_single_value_param(15)), true);
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(
                    std::size_t witness_amount,
                    std::size_t power,
                    std::size_t lambda
                ) {
                    std::size_t rows_amount = 0;
                    std::size_t poly_chunks = std::ceil(float(power) / 8);
                    std::size_t points_per_row = 0;

                    if( power < 8){
                        points_per_row = (witness_amount - power - 1) / 3;
                    } else {
                        points_per_row = (witness_amount - 8) / 5;
                    }
                    rows_amount = std::ceil(float(lambda) / points_per_row) * poly_chunks;
                    return rows_amount;
                }

                struct input_type {
                    std::vector<var> coefficients;
                    std::vector<var> points;
                    std::vector<var> values;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> result;
                        for (auto &coefficient : coefficients) {
                            result.push_back(coefficient);
                        }
                        for (auto &point : points) {
                            result.push_back(point);
                        }
                        for (auto &value : values) {
                            result.push_back(value);
                        }
                        return result;
                    }
                };

                struct result_type {
                    // fail if the check is not satisfied
                    result_type(const final_polynomial_check &component, std::uint32_t start_row_index) {}

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {};
                    }
                };

                template<typename ContainerType>
                final_polynomial_check(ContainerType witness, std::size_t power_, std::size_t lambda_) :
                    component_type(witness, {}, {}, get_manifest(power_, lambda_)),
                    power(power_), lambda(lambda_), rows_amount(get_rows_amount(witness.size(), power, lambda))
                {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                            typename PublicInputContainerType>
                final_polynomial_check(WitnessContainerType witness, ConstantContainerType constant,
                                       PublicInputContainerType public_input,
                                       std::size_t power_, std::size_t lambda_) :
                    component_type(witness, constant, public_input, get_manifest(power_, lambda_)),
                    power(power_), lambda(lambda_), rows_amount(get_rows_amount(witness.size(), power_, lambda_))
                {};

                final_polynomial_check(
                    std::initializer_list<typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    std::size_t power_, std::size_t lambda_) :
                    component_type(witnesses, constants, public_inputs, get_manifest(power_, lambda_)),
                    power(power_), lambda(lambda_), rows_amount(get_rows_amount(witnesses.size(), power, lambda))
                {};
            };

            template<typename BlueprintFieldType>
            using plonk_final_polynomial_check = final_polynomial_check<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

            template<typename BlueprintFieldType>
            typename plonk_final_polynomial_check<BlueprintFieldType>::result_type generate_assignments(
                const plonk_final_polynomial_check<BlueprintFieldType>
                    &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_final_polynomial_check<BlueprintFieldType>::input_type
                    instance_input,
                const std::size_t start_row_index) {

                using component_type = plonk_final_polynomial_check<BlueprintFieldType>;
                using expression_evaluator_type = typename component_type::expression_evaluator_type;
                using expression_evaluator_input_type = typename expression_evaluator_type::input_type;
                using var = typename component_type::var;
                using val = typename BlueprintFieldType::value_type;

                BOOST_ASSERT(instance_input.coefficients.size() == component.power + 1);
                BOOST_ASSERT(instance_input.points.size() == component.lambda);
                BOOST_ASSERT(instance_input.values.size() == 2 * component.lambda);

                std::size_t power = component.power;
                std::size_t lambda = component.lambda;
                std::size_t poly_chunks = std::ceil(float(power) / 8);
                std::size_t points_per_row = power < 8 ? (component.witness_amount() - power - 1) / 3: (component.witness_amount() - 8) / 5;
                std::size_t rows_amount = std::ceil(float(lambda) / points_per_row) * poly_chunks;
                var zero_var = var(component.C(0), start_row_index, false, var::column_type::constant);
                std::size_t row = start_row_index;
                std::size_t point = 0;

                if( power < 8){
                    for(std::size_t r = 0; r < rows_amount; r++){
                        for( std::size_t i = 0; i < power + 1; i++ ){
                            assignment.witness(component.W(i), row) = var_value(assignment, instance_input.coefficients[power - i]);
                        }
                        for( std::size_t i = 0; i < points_per_row; i++){
                            if( point >= lambda ) point = lambda - 1;
                            assignment.witness(component.W(power + 1 + 3 * i), row) = var_value(assignment, instance_input.points[point]);
                            assignment.witness(component.W(power + 1 + 3 * i + 1), row) = var_value(assignment, instance_input.values[2 * point]);
                            assignment.witness(component.W(power + 1 + 3 * i + 2), row) = var_value(assignment, instance_input.values[2 * point + 1]);
                            point++;
                        }
                        row++;
                    }
                } else {
                }
                return typename component_type::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType>
            typename plonk_final_polynomial_check<BlueprintFieldType>::result_type generate_circuit(
                const plonk_final_polynomial_check<BlueprintFieldType>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_final_polynomial_check<BlueprintFieldType>::input_type
                    instance_input,
                const std::size_t start_row_index) {

                using component_type = plonk_final_polynomial_check<BlueprintFieldType>;
                using expression_evaluator_type = typename component_type::expression_evaluator_type;
                using expression_evaluator_input_type = typename expression_evaluator_type::input_type;
                using var = typename component_type::var;

                if( instance_input.coefficients.size() != component.power + 1 )
                    std::cout << instance_input.coefficients.size() << " != " << component.power + 1 << std::endl;
                BOOST_ASSERT(instance_input.coefficients.size() == component.power + 1);
                BOOST_ASSERT(instance_input.points.size() == component.lambda);
                BOOST_ASSERT(instance_input.values.size() == 2 * component.lambda);

                using constraint_type = nil::crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;

                std::size_t power = component.power;
                std::size_t lambda = component.lambda;
                std::size_t poly_chunks = std::ceil(float(power) / 8);
                std::size_t points_per_row = power < 8 ? (component.witness_amount() - power - 1) / 3: (component.witness_amount() - 8) / 5;
                std::size_t rows_amount = std::ceil(float(lambda) / points_per_row) * poly_chunks;
                var zero_var = var(component.C(0), start_row_index, false, var::column_type::constant);
                std::size_t row = start_row_index;
                std::size_t point = 0;

                if( power < 8){
                    std::vector<constraint_type> constraints;

                    std::vector<var> coefficients; coefficients.resize(power + 1);
                    for( std::size_t i = 0; i < power + 1; i++ ){
                        coefficients[i] = var( component.W(i), 0);
                        for( std::size_t r = 0; r < rows_amount; r++ ){
                            bp.add_copy_constraint({var(component.W(i), start_row_index +r, false), instance_input.coefficients[power-i]});
                        }
                    }
                    for( std::size_t i = 0; i < points_per_row; i++){
                        var xs(component.W(power + 1 + 3 * i), 0 );
                        var y0(component.W(power + 1 + 3 * i + 1), 0 );
                        var y1(component.W(power + 1 + 3 * i + 2), 0 );
                        constraint_type y0_constr = coefficients[0];
                        constraint_type y1_constr = coefficients[0];
                        for( std::size_t j = 1; j < power + 1; j++ ){
                            y0_constr = coefficients[j] - y0_constr * xs;
                            y1_constr = coefficients[j] + y1_constr * xs;
                        }
                        y0_constr = y0 - y0_constr;
                        y1_constr = y1 - y1_constr;
                        constraints.push_back(y0_constr);
                        constraints.push_back(y1_constr);
                    }
                    std::size_t point = 0;
                    row = start_row_index;
                    for( std::size_t r = 0; r < rows_amount; r++ ){
                        for( std::size_t i = 0; i < points_per_row; i++){
                            bp.add_copy_constraint({var(component.W(power + 1 + 3 * i), row, false), instance_input.points[point]});
                            bp.add_copy_constraint({var(component.W(power + 1 + 3 * i + 1), row, false), instance_input.values[2 * point]});
                            bp.add_copy_constraint({var(component.W(power + 1 + 3 * i + 2), row, false), instance_input.values[2 * point + 1]});
                            point++;
                            if( point >= lambda ) break; // Will break both loops because rows amount is computed correctly.
                        }
                        row++;
                    }
                    std::size_t selector_id = bp.add_gate(constraints);
                    for( std::size_t i = 0; i < rows_amount; i++){
                        assignment.enable_selector(selector_id, start_row_index + i);
                    }
                } else {
                   BOOST_ASSERT("Not implemented");
                }
                return typename component_type::result_type(component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil