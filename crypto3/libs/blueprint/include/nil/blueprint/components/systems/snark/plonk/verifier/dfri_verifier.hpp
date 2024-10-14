//---------------------------------------------------------------------------//
// Copyright (c) 2024 Valeh Farzaliyev <estoniaa@nil.foundation>
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
// @file Distributed FRI verifier circuit component
//---------------------------------------------------------------------------//

#ifndef BLUEPRINT_COMPONENTS_DISTRIBUTED_VERIFIER_HPP
#define BLUEPRINT_COMPONENTS_DISTRIBUTED_VERIFIER_HPP

#include <map>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/proof.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/profiling.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

#include <nil/blueprint/components/systems/snark/plonk/verifier/dfri_proof_wrapper.hpp>
#include <nil/blueprint/components/systems/snark/plonk/verifier/dfri_proof_input_vars.hpp>
#include <nil/blueprint/components/systems/snark/plonk/verifier/final_polynomial_check.hpp>
#include <nil/blueprint/components/systems/snark/plonk/flexible/linear_check.hpp>
#include <nil/blueprint/components/systems/snark/plonk/flexible/poseidon.hpp>
#include <nil/blueprint/components/systems/snark/plonk/flexible/swap.hpp>
#include <nil/blueprint/components/systems/snark/plonk/flexible/constant_pow.hpp>
#include <nil/blueprint/components/systems/snark/plonk/flexible/colinear_checks.hpp>
#include <nil/blueprint/components/systems/snark/plonk/flexible/x_index.hpp>
#include <nil/blueprint/components/systems/snark/plonk/flexible/negate.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            template<typename BlueprintFieldType>
            class plonk_dfri_verifier : public plonk_component<BlueprintFieldType> {
            public:
                // using placeholder_info_type = nil::crypto3::zk::snark::placeholder_info<SrcParams>;
                using component_type = plonk_component<BlueprintFieldType>;
                using field_type = BlueprintFieldType;
                using val = typename BlueprintFieldType::value_type;
                using var = typename component_type::var;

                using poseidon_component_type = plonk_flexible_poseidon<BlueprintFieldType>;
                using swap_component_type = plonk_flexible_swap<BlueprintFieldType>;
                using colinear_checks_component_type = plonk_flexible_colinear_checks<BlueprintFieldType>;
                using constant_pow_component_type = plonk_flexible_constant_pow<BlueprintFieldType>;
                using x_index_component_type = plonk_flexible_x_index<BlueprintFieldType>;
                using negate_component_type = plonk_flexible_negate<BlueprintFieldType>;
                using dfri_linear_check_component_type = plonk_dfri_linear_check<BlueprintFieldType>;
                using final_polynomial_component_type = plonk_final_polynomial_check<BlueprintFieldType>;

                std::size_t rows_amount;    // calculator, please

                using fri_params_type = detail::dfri_component_params<field_type>;

                //              TODO: add constants from fixed batches. // TODO: think about them later
                //              It just costs a number of copy constraints and constant columns

                //              Full component input
                fri_params_type                                                         fri_params;
                std::map<std::size_t, std::size_t>                                      batches_sizes;
                std::size_t                                                             evaluation_points_amount;
                std::map<std::pair<std::size_t, std::size_t>, std::vector<std::size_t>> eval_map;    //(batch_id,poly_id) => point_id
                std::vector<std::pair<std::size_t, std::size_t>>                        ordered_eval_map; // = order_eval_map(eval_map, batches_sizes);   

                struct challenges_struct {
                    std::vector<var> fri_alphas;
                    std::vector<var> fri_xs;
                    var lpc_theta;
                };

                using input_type = detail::dfri_proof_input_vars<BlueprintFieldType>;

                struct result_type {
                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> result;
                        return result;
                    }
                };

                using manifest_type = plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                    std::size_t num_gates;

                public:
                    gate_manifest_type(
                        std::size_t witness_amount,
                        const fri_params_type &fri_params,
                        const std::map<std::size_t, std::size_t> &_batches_sizes,
                        std::size_t _evaluation_points_amount,
                        const std::map<std::pair<std::size_t, std::size_t>, std::vector<std::size_t>> &_eval_map) {
                        std::size_t m = 0;
                        for (const auto [k, v] : _eval_map) {
                            m += v.size();
                        }

                        num_gates = poseidon_component_type::get_gate_manifest(witness_amount).get_gates_amount();
                        num_gates += constant_pow_component_type::get_gate_manifest(
                                         witness_amount, (field_type::modulus - 1) / fri_params.domain_size)
                                         .get_gates_amount();
                        num_gates += constant_pow_component_type::get_gate_manifest(witness_amount, (1 << fri_params.r))
                                         .get_gates_amount();
                        num_gates +=
                            x_index_component_type::get_gate_manifest(witness_amount, log2(fri_params.domain_size) - 1)
                                .get_gates_amount();
                        num_gates += colinear_checks_component_type::get_gate_manifest(witness_amount, fri_params.r)
                                         .get_gates_amount();
                        num_gates += final_polynomial_component_type::get_gate_manifest(
                                         witness_amount,
                                         std::pow(2, std::log2(fri_params.max_degree + 1) - fri_params.r + 1) - 2,
                                         fri_params.lambda)
                                         .get_gates_amount();
                        num_gates +=
                            dfri_linear_check_component_type::get_gate_manifest(witness_amount, m).get_gates_amount();
                        num_gates += negate_component_type::get_gate_manifest(witness_amount, fri_params.lambda).get_gates_amount(); 
                    }
                    std::uint32_t gates_amount() const override {
                        return num_gates;
                    }
                };

                static gate_manifest get_gate_manifest(
                    std::size_t witness_amount,
                    const fri_params_type &fri_params,
                    const std::map<std::size_t, std::size_t> &batches_sizes,
                    std::size_t evaluation_points_amount,
                    const std::map<std::pair<std::size_t, std::size_t>, std::vector<std::size_t>> &eval_map) {
                    gate_manifest manifest = gate_manifest(gate_manifest_type(witness_amount, fri_params, batches_sizes,
                                                                              evaluation_points_amount, eval_map));
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest =
                        manifest_type(std::shared_ptr<manifest_param>(new manifest_single_value_param(15)), false);
                    return manifest;
                }

                // static std::size_t get_ordered_eval_map_size(const std::map<std::pair<std::size_t, std::size_t>,
                // std::vector<std::size_t>> &eval_map){
                //     std::vector<std::pair<std::size_t, std::size_t>> ordered_eval_map;
                //     for(const auto& [k, v] : component.eval_map){
                //         std::size_t polynomial_id = k.second + component.batches_sizes[k.first];
                //         for(const auto& point_id : v){
                //             ordered_eval_map.push_back({polynomial_id, point_id});
                //         }
                //     }
                //     return ordered_eval_map.size();
                // };

                static std::size_t get_rows_amount(
                    std::size_t witness_amount,
                    const fri_params_type &_fri_params,
                    const std::map<std::size_t, std::size_t> &_batches_sizes,
                    std::size_t _evaluation_points_amount,
                    const std::map<std::pair<std::size_t, std::size_t>, std::vector<std::size_t>> &_eval_map) {
                    std::size_t rows_amount = 0;
                    std::size_t poseidon_rows_amount = 0;
                    std::size_t constant_pow_rows_amount = 0;
                    std::size_t constant_pow2_rows_amount = 0;
                    std::size_t colinear_checks_rows_amount = 0;
                    std::size_t dfri_linear_check_rows_amount = 0;
                    std::size_t x_index_rows_amount = 0;

                    std::size_t m = 0;
                    for (const auto [k, v] : _eval_map) {
                        m += v.size();
                    }

                    std::size_t poseidon_rows = poseidon_component_type::get_rows_amount(witness_amount);
                    std::size_t constant_pow_rows = constant_pow_component_type::get_rows_amount(
                        witness_amount, (BlueprintFieldType::modulus - 1) / _fri_params.domain_size);
                    std::size_t constant_pow2_rows =
                        constant_pow_component_type::get_rows_amount(witness_amount, 1 << _fri_params.r);
                    std::size_t x_index_rows =
                        x_index_component_type::get_rows_amount(witness_amount, log2(_fri_params.domain_size) - 1);
                    std::size_t colinear_checks_rows =
                        colinear_checks_component_type::get_rows_amount(witness_amount, _fri_params.r);
                    std::size_t negate_rows = negate_component_type::get_rows_amount(witness_amount, _fri_params.lambda);
                    std::size_t dfri_linear_check_rows =
                        dfri_linear_check_component_type::get_rows_amount(witness_amount, m);
                    std::size_t final_polynomial_rows = final_polynomial_component_type::get_rows_amount(
                        witness_amount, std::pow(2, std::log2(_fri_params.max_degree + 1) - _fri_params.r + 1) - 3,
                        _fri_params.lambda);

                    for (std::size_t i = 0; i < _batches_sizes.size() / 2; i++) {
                        rows_amount += poseidon_rows;
                        poseidon_rows_amount += poseidon_rows;
                    }
                    if (_batches_sizes.size() % 2) {
                        rows_amount += poseidon_rows;
                        poseidon_rows_amount += poseidon_rows;
                    }

                    for (std::size_t i = 0; i < _fri_params.r; i++) {
                        rows_amount += poseidon_rows;
                        poseidon_rows_amount += poseidon_rows;
                    }
                    for (std::size_t i = 0; i < _fri_params.lambda; i++) {
                        rows_amount += poseidon_rows;
                        poseidon_rows_amount += poseidon_rows;
                    }

                    for (std::size_t i = 0; i < _fri_params.lambda; i++) {
                        rows_amount += constant_pow_rows;
                        rows_amount += constant_pow2_rows;
                        constant_pow_rows_amount += constant_pow_rows;
                        constant_pow2_rows_amount += constant_pow2_rows;
                    }
                    for (std::size_t i = 0; i < _fri_params.lambda; i++) {
                        rows_amount += x_index_rows;
                        x_index_rows_amount += x_index_rows;
                    }

                    rows_amount +=  negate_rows;
                    for (std::size_t i = 0; i < _fri_params.lambda; i++) {
                        rows_amount += 2 * dfri_linear_check_rows;
                        dfri_linear_check_rows_amount += 2 * dfri_linear_check_rows;
                    }
                    for (std::size_t i = 0; i < _fri_params.lambda; i++) {
                        rows_amount += colinear_checks_rows;
                        colinear_checks_rows_amount += colinear_checks_rows;
                    }
                    for (std::size_t i = 0; i < _fri_params.lambda; i++) {
                        for (const auto &[batch_id, batch_size] : _batches_sizes) {
                            for (std::size_t k = 0; k < batch_size; k++) {
                                rows_amount += poseidon_rows;
                                poseidon_rows_amount += poseidon_rows;
                            }
                            for (std::size_t k = 0; k < log2(_fri_params.domain_size) - 1; k++) {
                                rows_amount += poseidon_rows;
                                poseidon_rows_amount += poseidon_rows;
                            }
                        }
                        for (std::size_t j = 0; j < _fri_params.r; j++) {
                            // if(j != 0){ // Remove if when linear combination computation will be finished
                            rows_amount += poseidon_rows;
                            poseidon_rows_amount += poseidon_rows;
                            for (std::size_t k = 0; k < log2(_fri_params.domain_size) - 1 - j; k++) {
                                rows_amount += poseidon_rows;
                                poseidon_rows_amount += poseidon_rows;
                            }
                            // }
                        }
                    }
                    // std::cout << "get_rows_amount:" << rows_amount << std::endl;
                    rows_amount += final_polynomial_rows;
                    std::cout << "Component rows (without swaps):" << rows_amount << std::endl;
                    std::cout << "\tposeidon rows         = " << poseidon_rows_amount << std::endl;
                    std::cout << "\tfinal_polynomial_rows = " << final_polynomial_rows
                              << std::endl;    // Called only once
                    std::cout << "\tconstant_pow_rows     = " << constant_pow_rows_amount << std::endl;
                    std::cout << "\tconstant_pow2_rows    = " << constant_pow2_rows_amount << std::endl;
                    std::cout << "\tx_index_rows          = " << x_index_rows_amount << std::endl;
                    std::cout << "\tcolinear_checks_rows  = " << colinear_checks_rows_amount << std::endl;
                    std::cout << "\tnegate rows           = " << negate_rows << std::endl;
                    std::cout << "\tdfri_linear_check_rows  = " << dfri_linear_check_rows_amount << std::endl;
                    return rows_amount;
                }

                // Subcomponents list
                poseidon_component_type poseidon_instance;
                constant_pow_component_type constant_pow_instance;
                constant_pow_component_type constant_pow2_instance;
                x_index_component_type x_index_instance;
                colinear_checks_component_type colinear_checks_instance;
                final_polynomial_component_type final_polynomial_instance;
                dfri_linear_check_component_type dfri_linear_check_instance;
                negate_component_type negate_instance;

                static std::vector<std::pair<std::size_t, std::size_t>> order_eval_map(
                    const std::map<std::pair<std::size_t, std::size_t>, std::vector<std::size_t>> &eval_map,
                    const std::map<std::size_t, std::size_t> &batches_sizes) {

                    std::vector<std::pair<std::size_t, std::size_t>> ordered_eval_map;
                    std::map<std::size_t, std::size_t> offsets;
                    std::size_t offset = 0;
                    for (const auto &[k, v] : batches_sizes) {
                        offsets[k] = offset;
                        offset += v;
                    }
                    
                    for (const auto &[k, v] : eval_map) {
                        std::size_t polynomial_id = k.second + offsets[k.first];
                        for (const auto &point_id : v) {
                            ordered_eval_map.push_back({polynomial_id, point_id});
                        }
                    }
                    std::sort(ordered_eval_map.begin(), ordered_eval_map.end(),
                              [](const std::pair<std::size_t, std::size_t> &left,
                                 const std::pair<std::size_t, std::size_t> &right) {
                                  return left.second < right.second ||
                                         (left.second == right.second && left.first < right.first);
                              });

                    return ordered_eval_map;
                }

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                plonk_dfri_verifier(
                    WitnessContainerType witnesses,
                    ConstantContainerType constants,
                    PublicInputContainerType public_inputs,
                    const fri_params_type &_fri_params,
                    const std::map<std::size_t, std::size_t> &_batches_sizes,
                    std::size_t _evaluation_points_amount,
                    const std::map<std::pair<std::size_t, std::size_t>, std::vector<std::size_t>> &_eval_map) :
                    component_type(witnesses, constants, public_inputs, get_manifest()), fri_params(_fri_params),
                    poseidon_instance(witnesses, constants, public_inputs),
                    constant_pow_instance(witnesses, constants, public_inputs,(BlueprintFieldType::modulus - 1) / fri_params.domain_size),
                    constant_pow2_instance(witnesses, constants, public_inputs, 1 << fri_params.r),
                    x_index_instance(witnesses, constants, public_inputs, log2(fri_params.domain_size) - 1, fri_params.omega),
                    colinear_checks_instance(witnesses, constants, public_inputs, fri_params.r),
                    final_polynomial_instance(witnesses, constants, public_inputs, std::pow(2, std::log2(fri_params.max_degree + 1) - fri_params.r + 1) - 3, fri_params.lambda),
                    negate_instance(witnesses, constants, public_inputs, fri_params.lambda),
                    batches_sizes(_batches_sizes), 
                    evaluation_points_amount(_evaluation_points_amount),
                    eval_map(_eval_map),
                    ordered_eval_map(order_eval_map(_eval_map, _batches_sizes)),
                    dfri_linear_check_instance(witnesses, constants, public_inputs, ordered_eval_map.size(), ordered_eval_map) {

                        rows_amount = get_rows_amount(witnesses.size(), fri_params, batches_sizes, evaluation_points_amount, eval_map);
                }

                std::vector<std::uint32_t> all_witnesses() const {
                    return this->_W;
                }
            };

            template<typename BlueprintFieldType>
            typename plonk_dfri_verifier<BlueprintFieldType>::result_type generate_assignments(
                const plonk_dfri_verifier<BlueprintFieldType> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename plonk_dfri_verifier<BlueprintFieldType>::input_type instance_input,
                const std::uint32_t start_row_index) {
                using component_type = plonk_dfri_verifier<BlueprintFieldType>;
                using poseidon_component_type = typename component_type::poseidon_component_type;
                using constant_pow_component_type = typename component_type::constant_pow_component_type;
                using x_index_component_type = typename component_type::x_index_component_type;
                using colinear_checks_component_type = typename component_type::colinear_checks_component_type;
                using dfri_linear_check_component_type = typename component_type::dfri_linear_check_component_type;
                using swap_component_type = typename component_type::swap_component_type;
                using swap_input_type = typename swap_component_type::input_type;
                using final_polynomial_component_type = typename component_type::final_polynomial_component_type;
                using negate_component_type = typename component_type::negate_component_type;
                using var = typename component_type::var;

                var zero_var = var(component.C(0), start_row_index, false, var::column_type::constant);
                std::size_t row = start_row_index;

                // Just for testing. Add row computation for each subcomponent.
                std::size_t poseidon_rows = 0;
                std::size_t constant_pow_rows = 0;
                std::size_t swap_rows = 0;

                typename component_type::challenges_struct c;
                typename poseidon_component_type::input_type poseidon_input;
                typename poseidon_component_type::result_type poseidon_output;
                const auto &poseidon_instance = component.poseidon_instance;
                const auto &constant_pow_instance = component.constant_pow_instance;
                const auto &constant_pow2_instance = component.constant_pow2_instance;
                const auto &x_index_instance = component.x_index_instance;
                const auto &colinear_checks_instance = component.colinear_checks_instance;
                const auto &dfri_linear_check_instance = component.dfri_linear_check_instance;
                const auto &final_polynomial_instance = component.final_polynomial_instance;
                const auto &fri_params = component.fri_params;
                const auto &negate_instance = component.negate_instance;
                poseidon_input.input_state[0] = instance_input.initial_transcript_state;

                // Transcript(commitments)
                for (std::size_t i = 0; i < instance_input.commitments_vector.size() / 2; i++) {
                    poseidon_input.input_state[1] = instance_input.commitments_vector[i * 2];
                    poseidon_input.input_state[2] = instance_input.commitments_vector[i * 2 + 1];
                    poseidon_output = generate_assignments(poseidon_instance, assignment, poseidon_input, row);
                    poseidon_input.input_state[0] = poseidon_output.output_state[2];
                    row += poseidon_instance.rows_amount;
                    poseidon_rows += poseidon_instance.rows_amount;
                }
                if (instance_input.commitments_vector.size() % 2) {
                    poseidon_input.input_state[1] =
                        instance_input.commitments_vector[instance_input.commitments_vector.size() - 1];
                    poseidon_input.input_state[2] = zero_var;
                    poseidon_output = generate_assignments(poseidon_instance, assignment, poseidon_input, row);
                    poseidon_input.input_state[0] = poseidon_output.output_state[2];
                    row += poseidon_instance.rows_amount;
                    poseidon_rows += poseidon_instance.rows_amount;
                }
                // lpc_theta = transcript.challenge()

                c.lpc_theta = poseidon_output.output_state[2];

                for (std::size_t i = 0; i < fri_params.r; i++) {
                    poseidon_input = {poseidon_output.output_state[2], instance_input.fri_roots[i], zero_var};
                    poseidon_output = generate_assignments(poseidon_instance, assignment, poseidon_input, row);
                    c.fri_alphas.push_back(poseidon_output.output_state[2]);
                    row += poseidon_instance.rows_amount;
                    poseidon_rows += poseidon_instance.rows_amount;
                }

                for (std::size_t i = 0; i < fri_params.lambda; i++) {
                    poseidon_input = {poseidon_output.output_state[2], zero_var, zero_var};
                    poseidon_output = generate_assignments(poseidon_instance, assignment, poseidon_input, row);
                    c.fri_xs.push_back(poseidon_output.output_state[2]);
                    row += poseidon_instance.rows_amount;
                    poseidon_rows += poseidon_instance.rows_amount;
                }

                std::vector<var> xs;
                std::vector<var> xf;
                for (std::size_t i = 0; i < fri_params.lambda; i++) {
                    typename constant_pow_component_type::input_type constant_pow_input = {c.fri_xs[i]};
                    typename constant_pow_component_type::result_type constant_pow_output =
                        generate_assignments(constant_pow_instance, assignment, constant_pow_input, row);
                    xs.push_back(constant_pow_output.y);
                    row += constant_pow_instance.rows_amount;
                    constant_pow_rows += constant_pow_instance.rows_amount;

                    constant_pow_input = {xs[i]};
                    constant_pow_output =
                        generate_assignments(constant_pow2_instance, assignment, constant_pow_input, row);
                    xf.push_back(constant_pow_output.y);
                    row += constant_pow2_instance.rows_amount;
                    constant_pow_rows += constant_pow2_instance.rows_amount;
                }

                // check correspondence between x, x_index and merkle path
                std::vector<var> x_indices;
                for (std::size_t i = 0; i < fri_params.lambda; i++) {
                    typename x_index_component_type::input_type x_index_input;
                    x_index_input.x = xs[i];
                    for (std::size_t j = 0; j < log2(fri_params.domain_size) - 1; j++) {
                        x_index_input.b.push_back(instance_input.merkle_tree_positions[i][j]);
                    }
                    typename x_index_component_type::result_type x_index_output =
                        generate_assignments(x_index_instance, assignment, x_index_input, row);
                    row += x_index_instance.rows_amount;
                    x_indices.push_back(x_index_output.b0);
                }

                typename negate_component_type::input_type negate_input = {xs};
                typename negate_component_type::result_type negate_output = generate_assignments(negate_instance, assignment, negate_input, row);
                row += negate_instance.rows_amount;
                BOOST_ASSERT(negate_output.output.size() == fri_params.lambda);

                typename dfri_linear_check_component_type::input_type linear_check_input;
                linear_check_input.theta = c.lpc_theta;
                linear_check_input.xi = instance_input.evaluation_points;
                linear_check_input.z = instance_input.evaluations;

                std::vector<var> linearity_check_outputs;
                for (std::size_t i = 0; i < component.fri_params.lambda; i++) {
                    swap_input_type swap_input;
                    swap_input.inp = {x_indices[i], xs[i], negate_output.output[i]};
                    auto swap_result = assignment.template add_input_to_batch<swap_component_type>(swap_input, 0);
                    linear_check_input.x = swap_result.output[1];
                    linear_check_input.y = {};
                    std::size_t cur = 0;
                    for (const auto &[k, v] : component.batches_sizes) {
                        for (std::size_t j = 0; j < v; j++, cur += 2) {
                            linear_check_input.y.push_back(instance_input.initial_proof_values[i][cur]);
                        }
                    }
                    typename dfri_linear_check_component_type::result_type linear_check_result =
                        generate_assignments(dfri_linear_check_instance, assignment, linear_check_input, row);
                    row += dfri_linear_check_instance.rows_amount;
                    linearity_check_outputs.push_back(linear_check_result.output);

                    linear_check_input.x = swap_result.output[0];
                    linear_check_input.y = {};
                    cur = 1;
                    for (const auto &[k, v] : component.batches_sizes) {
                        for (std::size_t j = 0; j < v; j++, cur += 2) {
                            linear_check_input.y.push_back(instance_input.initial_proof_values[i][cur]);
                        }
                    }
                    linear_check_result =
                        generate_assignments(dfri_linear_check_instance, assignment, linear_check_input, row);
                    row += dfri_linear_check_instance.rows_amount;
                    linearity_check_outputs.push_back(linear_check_result.output);
                }

                // Colinear checks
                std::size_t colinear_checks_rows = 0;
                for (std::size_t i = 0; i < fri_params.lambda; i++) {
                    typename colinear_checks_component_type::input_type colinear_checks_input(component.fri_params.r);
                    colinear_checks_input.x = xs[i];
                    colinear_checks_input.ys.push_back(linearity_check_outputs[2 * i]);
                    colinear_checks_input.ys.push_back(linearity_check_outputs[2 * i + 1]);
                    colinear_checks_input.bs.push_back(x_indices[i]);
                    for (std::size_t j = 0; j < fri_params.r; j++) {
                        colinear_checks_input.ys.push_back(instance_input.round_proof_values[i][2 * j]);
                        colinear_checks_input.ys.push_back(instance_input.round_proof_values[i][2 * j + 1]);
                        colinear_checks_input.alphas.push_back(c.fri_alphas[j]);
                        colinear_checks_input.bs.push_back(
                            instance_input
                                .merkle_tree_positions[i][instance_input.merkle_tree_positions[i].size() - j - 1]);
                    }
                    typename colinear_checks_component_type::result_type colinear_checks_output =
                        generate_assignments(colinear_checks_instance, assignment, colinear_checks_input, row);
                    row += colinear_checks_instance.rows_amount;
                    colinear_checks_rows += colinear_checks_instance.rows_amount;
                }

                const auto &batches_sizes = component.batches_sizes;
                std::size_t merkle_leaf_rows = 0;
                std::size_t merkle_proof_rows = 0;
                // Query Merkle proofs
                std::vector<var> final_polynomial_evals;
                for (std::size_t i = 0; i < fri_params.lambda; i++) {
                    std::size_t cur = 0;
                    std::size_t cur_hash = 0;
                    for (const auto &[batch_id, batch_size] : batches_sizes) {
                        poseidon_input.input_state[0] = zero_var;
                        for (std::size_t k = 0; k < batch_size; k++, cur += 2) {
                            poseidon_input.input_state[1] = instance_input.initial_proof_values[i][cur];
                            poseidon_input.input_state[2] = instance_input.initial_proof_values[i][cur + 1];
                            //                            std::cout << "\t" << var_value(assignment,
                            //                            poseidon_input.input_state[1]) << "\t" <<
                            //                            var_value(assignment, poseidon_input.input_state[2]) <<
                            //                            std::endl;
                            poseidon_output = generate_assignments(poseidon_instance, assignment, poseidon_input, row);
                            poseidon_input.input_state[0] = poseidon_output.output_state[2];
                            row += poseidon_instance.rows_amount;
                            poseidon_rows += poseidon_instance.rows_amount;
                            merkle_leaf_rows += poseidon_instance.rows_amount;
                        }
                        var hash_var = poseidon_output.output_state[2];
                        //                        std::cout << "Leaf hash = " << var_value(assignment, hash_var) <<
                        //                        std::endl; std::cout << "First hash i = " << i << "; cur_hash = " <<
                        //                        cur_hash << " = " << instance_input.initial_proof_hashes[i][cur_hash]
                        //                        << " = " << var_value(assignment,
                        //                        instance_input.initial_proof_hashes[i][cur_hash]) << std::endl;
                        for (std::size_t k = 0; k < log2(fri_params.domain_size) - 1; k++) {
                            swap_input_type swap_input;
                            swap_input.inp = {instance_input.merkle_tree_positions[i][k],
                                              instance_input.initial_proof_hashes[i][cur_hash], hash_var};
                            auto swap_result =
                                assignment.template add_input_to_batch<swap_component_type>(swap_input, 0);
                            poseidon_input = {zero_var, swap_result.output[0], swap_result.output[1]};
                            poseidon_output = generate_assignments(poseidon_instance, assignment, poseidon_input, row);
                            //                            std::cout << "\t("
                            //                                << var_value(assignment, poseidon_input.input_state[1]) <<
                            //                                ", "
                            //                                << var_value(assignment, poseidon_input.input_state[2]) <<
                            //                                ", "
                            //                                << ") => " << var_value(assignment,
                            //                                poseidon_output.output_state[2]) << std::endl;
                            hash_var = poseidon_output.output_state[2];
                            cur_hash++;
                            row += poseidon_instance.rows_amount;
                            poseidon_rows += poseidon_instance.rows_amount;
                            merkle_proof_rows += poseidon_instance.rows_amount;
                        }
                    }

                    // Round proofs
                    cur = 0;
                    cur_hash = 0;
                    var hash_var;
                    var y0 = linearity_check_outputs[2 * i];
                    var y1 = linearity_check_outputs[2 * i + 1];
                    for (std::size_t j = 0; j < fri_params.r; j++) {
                        poseidon_input = {zero_var, y0, y1};
                        poseidon_output = generate_assignments(poseidon_instance, assignment, poseidon_input, row);
                        hash_var = poseidon_output.output_state[2];
                        row += poseidon_instance.rows_amount;
                        poseidon_rows += poseidon_instance.rows_amount;
                        merkle_proof_rows += poseidon_instance.rows_amount;
                        for (std::size_t k = 0; k < log2(fri_params.domain_size) - 1 - j; k++) {
                            swap_input_type swap_input;
                            swap_input.inp = {instance_input.merkle_tree_positions[i][k],
                                              instance_input.round_proof_hashes[i][cur_hash], hash_var};
                            auto swap_result =
                                assignment.template add_input_to_batch<swap_component_type>(swap_input, 0);
                            poseidon_input = {zero_var, swap_result.output[0], swap_result.output[1]};
                            poseidon_output = generate_assignments(poseidon_instance, assignment, poseidon_input, row);
                            row += poseidon_instance.rows_amount;
                            poseidon_rows += poseidon_instance.rows_amount;
                            merkle_proof_rows += poseidon_instance.rows_amount;
                            hash_var = poseidon_output.output_state[2];
                            cur_hash++;
                        }

                        y0 = instance_input.round_proof_values[i][cur * 2];
                        y1 = instance_input.round_proof_values[i][cur * 2 + 1];
                        cur++;
                    }
                    swap_input_type swap_input;
                    swap_input.inp = {
                        instance_input.merkle_tree_positions[i][log2(fri_params.domain_size) - 1 - fri_params.r], y0,
                        y1};
                    auto swap_result = assignment.template add_input_to_batch<swap_component_type>(swap_input, 0);
                    final_polynomial_evals.push_back(swap_result.output[0]);
                    final_polynomial_evals.push_back(swap_result.output[1]);
                }

                typename final_polynomial_component_type::input_type final_polynomial_input = {
                    instance_input.final_polynomial, xf, final_polynomial_evals};
                generate_assignments(final_polynomial_instance, assignment, final_polynomial_input, row);
                row += final_polynomial_instance.rows_amount;

                const typename component_type::result_type result;
                return result;
            }


            template<typename BlueprintFieldType>
            const typename plonk_dfri_verifier<BlueprintFieldType>::result_type generate_circuit(
                const plonk_dfri_verifier<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename plonk_dfri_verifier<BlueprintFieldType>::input_type &instance_input,
                const std::size_t start_row_index) {
                using component_type = plonk_dfri_verifier<BlueprintFieldType>;
                using poseidon_component_type = typename component_type::poseidon_component_type;
                using constant_pow_component_type = typename component_type::constant_pow_component_type;
                using x_index_component_type = typename component_type::x_index_component_type;
                using colinear_checks_component_type = typename component_type::colinear_checks_component_type;
                using dfri_linear_check_component_type = typename component_type::dfri_linear_check_component_type;
                using constraint_type = nil::crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using swap_component_type = typename component_type::swap_component_type;
                using swap_input_type = typename swap_component_type::input_type;
                using final_polynomial_component_type = typename component_type::final_polynomial_component_type;
                using negate_component_type = typename component_type::negate_component_type;
                using var = typename component_type::var;

                assignment.constant(0, start_row_index) = 0;    // Zero constant
                var zero_var = var(component.C(0), start_row_index, false, var::column_type::constant);
                std::size_t row = start_row_index;

                std::size_t rows = 0;
                std::size_t poseidon_rows = 0;

                const auto &poseidon_instance = component.poseidon_instance;
                const auto &constant_pow_instance = component.constant_pow_instance;
                const auto &constant_pow2_instance = component.constant_pow2_instance;
                const auto &x_index_instance = component.x_index_instance;
                const auto &colinear_checks_instance = component.colinear_checks_instance;
                const auto &dfri_linear_check_instance = component.dfri_linear_check_instance;
                const auto &final_polynomial_instance = component.final_polynomial_instance;
                const auto &negate_instance = component.negate_instance;
                const auto &fri_params = component.fri_params;

                typename component_type::challenges_struct c;
                typename poseidon_component_type::input_type poseidon_input;
                typename poseidon_component_type::result_type poseidon_output;
                poseidon_input.input_state[0] = instance_input.initial_transcript_state;

                // Transcript(commitments)
                for (std::size_t i = 0; i < instance_input.commitments_vector.size() / 2; i++) {
                    poseidon_input.input_state[1] = instance_input.commitments_vector[i * 2];
                    poseidon_input.input_state[2] = instance_input.commitments_vector[i * 2 + 1];
                    poseidon_output = generate_circuit(poseidon_instance, bp, assignment, poseidon_input, row);
                    poseidon_input.input_state[0] = poseidon_output.output_state[2];
                    row += poseidon_instance.rows_amount;
                    poseidon_rows += poseidon_instance.rows_amount;
                }
                if (instance_input.commitments_vector.size() % 2) {
                    poseidon_input.input_state[1] =
                        instance_input.commitments_vector[instance_input.commitments_vector.size() - 1];
                    poseidon_input.input_state[2] = zero_var;
                    poseidon_output = generate_circuit(poseidon_instance, bp, assignment, poseidon_input, row);
                    poseidon_input.input_state[0] = poseidon_output.output_state[2];
                    row += poseidon_instance.rows_amount;
                    poseidon_rows += poseidon_instance.rows_amount;
                }
                // lpc_theta = transcript.challenge()
                c.lpc_theta = poseidon_output.output_state[2];

                for (std::size_t i = 0; i < fri_params.r; i++) {
                    poseidon_input = {poseidon_output.output_state[2], instance_input.fri_roots[i], zero_var};
                    poseidon_output = generate_circuit(poseidon_instance, bp, assignment, poseidon_input, row);
                    c.fri_alphas.push_back(poseidon_output.output_state[2]);
                    row += poseidon_instance.rows_amount;
                }

                for (std::size_t i = 0; i < fri_params.lambda; i++) {
                    poseidon_input = {poseidon_output.output_state[2], zero_var, zero_var};
                    poseidon_output = generate_circuit(poseidon_instance, bp, assignment, poseidon_input, row);
                    c.fri_xs.push_back(poseidon_output.output_state[2]);
                    row += poseidon_instance.rows_amount;
                }

                std::vector<var> xs;
                std::vector<var> xf;
                for (std::size_t i = 0; i < fri_params.lambda; i++) {
                    typename constant_pow_component_type::input_type constant_pow_input = {c.fri_xs[i]};
                    typename constant_pow_component_type::result_type constant_pow_output =
                        generate_circuit(constant_pow_instance, bp, assignment, constant_pow_input, row);
                    xs.push_back(constant_pow_output.y);
                    row += constant_pow_instance.rows_amount;

                    constant_pow_input = {xs[i]};
                    constant_pow_output =
                        generate_circuit(constant_pow2_instance, bp, assignment, constant_pow_input, row);
                    xf.push_back(constant_pow_output.y);
                    row += constant_pow2_instance.rows_amount;
                }

                std::vector<var> x_indices;
                for (std::size_t i = 0; i < fri_params.lambda; i++) {
                    typename x_index_component_type::input_type x_index_input;
                    x_index_input.x = xs[i];
                    for (std::size_t j = 0; j < log2(fri_params.domain_size) - 1; j++) {
                        x_index_input.b.push_back(instance_input.merkle_tree_positions[i][j]);
                    }
                    typename x_index_component_type::result_type x_index_output =
                        generate_circuit(x_index_instance, bp, assignment, x_index_input, row);
                    row += x_index_instance.rows_amount;
                    x_indices.push_back(x_index_output.b0);
                }

                typename negate_component_type::input_type negate_input = {xs};
                typename negate_component_type::result_type negate_output = generate_circuit(negate_instance, bp, assignment, negate_input, row);
                row += negate_instance.rows_amount;
                BOOST_ASSERT(negate_output.output.size() == fri_params.lambda);

                typename dfri_linear_check_component_type::input_type linear_check_input;
                linear_check_input.theta = c.lpc_theta;
                linear_check_input.xi = instance_input.evaluation_points;
                linear_check_input.z = instance_input.evaluations;

                std::vector<var> linearity_check_outputs = {};
                for (std::size_t i = 0; i < component.fri_params.lambda; i++) {
                    std::size_t cur = 0;
                    swap_input_type swap_input;
                    swap_input.inp = {x_indices[i], xs[i], negate_output.output[i]};
                    auto swap_result = assignment.template add_input_to_batch<swap_component_type>(swap_input, 1);
                    linear_check_input.x = swap_result.output[1];
                    linear_check_input.y = {};
                    for (const auto &[k, v] : component.batches_sizes) {
                        for (std::size_t j = 0; j < v; j++, cur += 2) {
                            linear_check_input.y.push_back(instance_input.initial_proof_values[i][cur]);
                        }
                    }
                    typename dfri_linear_check_component_type::result_type linear_check_result =
                        generate_circuit(dfri_linear_check_instance, bp, assignment, linear_check_input, row);
                    row += dfri_linear_check_instance.rows_amount;
                    linearity_check_outputs.push_back(linear_check_result.output);

                    linear_check_input.x = swap_result.output[0];
                    linear_check_input.y = {};
                    cur = 1;
                    for (const auto &[k, v] : component.batches_sizes) {
                        for (std::size_t j = 0; j < v; j++, cur += 2) {
                            linear_check_input.y.push_back(instance_input.initial_proof_values[i][cur]);
                        }
                    }
                    linear_check_result =
                        generate_circuit(dfri_linear_check_instance, bp, assignment, linear_check_input, row);
                    row += dfri_linear_check_instance.rows_amount;
                    linearity_check_outputs.push_back(linear_check_result.output);
                }

                // Colinear checks
                for (std::size_t i = 0; i < component.fri_params.lambda; i++) {
                    typename colinear_checks_component_type::input_type colinear_checks_input(component.fri_params.r);
                    colinear_checks_input.x = xs[i];
                    colinear_checks_input.ys.push_back(linearity_check_outputs[2 * i]);
                    colinear_checks_input.ys.push_back(linearity_check_outputs[2 * i + 1]);
                    colinear_checks_input.bs.push_back(x_indices[i]);
                    for (std::size_t j = 0; j < component.fri_params.r; j++) {
                        colinear_checks_input.ys.push_back(instance_input.round_proof_values[i][2 * j]);
                        colinear_checks_input.ys.push_back(instance_input.round_proof_values[i][2 * j + 1]);
                        colinear_checks_input.alphas.push_back(c.fri_alphas[j]);
                        colinear_checks_input.bs.push_back(
                            instance_input
                                .merkle_tree_positions[i][instance_input.merkle_tree_positions[i].size() - j - 1]);
                    }
                    typename colinear_checks_component_type::result_type colinear_checks_output =
                        generate_circuit(colinear_checks_instance, bp, assignment, colinear_checks_input, row);
                    row += colinear_checks_instance.rows_amount;
                }

                // Query Merkle proofs
                const auto &batches_sizes = component.batches_sizes;
                std::vector<var> final_polynomial_evals;
                for (std::size_t i = 0; i < fri_params.lambda; i++) {
                    std::size_t cur = 0;
                    std::size_t cur_hash = 0;
                    for (const auto &[batch_id, batch_size] : batches_sizes) {
                        poseidon_input.input_state[0] = zero_var;
                        for (std::size_t k = 0; k < batch_size; k++, cur += 2) {
                            poseidon_input.input_state[1] = instance_input.initial_proof_values[i][cur];
                            poseidon_input.input_state[2] = instance_input.initial_proof_values[i][cur + 1];
                            poseidon_output = generate_circuit(poseidon_instance, bp, assignment, poseidon_input, row);
                            poseidon_input.input_state[0] = poseidon_output.output_state[2];
                            row += poseidon_instance.rows_amount;
                        }
                        var hash_var = poseidon_output.output_state[2];
                        for (std::size_t k = 0; k < log2(fri_params.domain_size) - 1; k++) {
                            swap_input_type swap_input;
                            swap_input.inp = {instance_input.merkle_tree_positions[i][k],
                                              instance_input.initial_proof_hashes[i][cur_hash], hash_var};
                            auto swap_result =
                                assignment.template add_input_to_batch<swap_component_type>(swap_input, 1);
                            poseidon_input = {zero_var, swap_result.output[0], swap_result.output[1]};
                            poseidon_output = generate_circuit(poseidon_instance, bp, assignment, poseidon_input, row);
                            hash_var = poseidon_output.output_state[2];
                            cur_hash++;
                            row += poseidon_instance.rows_amount;
                        }
                        bp.add_copy_constraint(
                            {poseidon_output.output_state[2], instance_input.commitments.at(batch_id)});
                    }

                    // Compute y-s for first round
                    // Round proofs
                    cur = 0;
                    cur_hash = 0;
                    var hash_var;
                    var y0 = linearity_check_outputs[2 * i];
                    var y1 = linearity_check_outputs[2 * i + 1];

                    for (std::size_t j = 0; j < fri_params.r; j++) {
                        poseidon_input = {zero_var, y0, y1};
                        poseidon_output = generate_circuit(poseidon_instance, bp, assignment, poseidon_input, row);
                        hash_var = poseidon_output.output_state[2];
                        row += poseidon_instance.rows_amount;
                        for (std::size_t k = 0; k < log2(fri_params.domain_size) - 1 - j; k++) {
                            swap_input_type swap_input;
                            swap_input.inp = {instance_input.merkle_tree_positions[i][k],
                                              instance_input.round_proof_hashes[i][cur_hash], hash_var};
                            auto swap_result =
                                assignment.template add_input_to_batch<swap_component_type>(swap_input, 1);
                            poseidon_input = {zero_var, swap_result.output[0], swap_result.output[1]};
                            poseidon_output = generate_circuit(poseidon_instance, bp, assignment, poseidon_input, row);
                            row += poseidon_instance.rows_amount;
                            hash_var = poseidon_output.output_state[2];
                            cur_hash++;
                        }
                        bp.add_copy_constraint({poseidon_output.output_state[2], instance_input.fri_roots[j]});

                        y0 = instance_input.round_proof_values[i][cur * 2];
                        y1 = instance_input.round_proof_values[i][cur * 2 + 1];
                        cur++;
                    }
                    swap_input_type swap_input;
                    swap_input.inp = {
                        instance_input.merkle_tree_positions[i][log2(fri_params.domain_size) - 1 - fri_params.r], y0,
                        y1};
                    auto swap_result = assignment.template add_input_to_batch<swap_component_type>(swap_input, 1);
                    final_polynomial_evals.push_back(swap_result.output[0]);
                    final_polynomial_evals.push_back(swap_result.output[1]);
                }

                typename final_polynomial_component_type::input_type final_polynomial_input = {
                    instance_input.final_polynomial, xf, final_polynomial_evals};
                generate_circuit(final_polynomial_instance, bp, assignment, final_polynomial_input, row);
                row += final_polynomial_instance.rows_amount;

                const typename component_type::result_type result;
                return result;
            }
        }    // namespace components
    }    // namespace blueprint
}    // namespace nil

#endif
