//---------------------------------------------------------------------------//
// Copyright (c) 2024 Valeh Farzaliyev <estoniaa@nil.foundation>
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
#include <nil/blueprint/components/systems/snark/plonk/flexible/linear_check.hpp>
#include <nil/blueprint/components/systems/snark/plonk/flexible/poseidon.hpp>
#include <nil/blueprint/components/systems/snark/plonk/flexible/swap.hpp>
#include <nil/blueprint/components/systems/snark/plonk/flexible/constant_pow.hpp>
#include <nil/blueprint/components/systems/snark/plonk/flexible/colinear_checks.hpp>
#include <nil/blueprint/components/systems/snark/plonk/flexible/x_index.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            template<typename BlueprintFieldType>
            class plonk_dfri_verifier: public plonk_component<BlueprintFieldType>{
            public:
                //using placeholder_info_type = nil::crypto3::zk::snark::placeholder_info<SrcParams>;
                using component_type =  plonk_component<BlueprintFieldType>;
                using field_type = BlueprintFieldType;
                using val = typename BlueprintFieldType::value_type;
                using var = typename component_type::var;

                using poseidon_component_type = plonk_flexible_poseidon<BlueprintFieldType>;
                using swap_component_type = plonk_flexible_swap<BlueprintFieldType>;
                using colinear_checks_component_type = plonk_flexible_colinear_checks<BlueprintFieldType>;
                using constant_pow_component_type = plonk_flexible_constant_pow<BlueprintFieldType>;
                using x_index_component_type = plonk_flexible_x_index<BlueprintFieldType>;
                using dfri_linear_check_component_type = plonk_dfri_linear_check<BlueprintFieldType>;

                std::size_t rows_amount; // calculator, please

                using fri_params_type = detail::dfri_component_params<field_type>;

//              TODO: add constants from fixed batches. // TODO: think about them later
//              It just costs a number of copy constraints and constant columns

//              Full component input
                fri_params_type                                             fri_params;
                std::map<std::size_t, std::size_t>                          batches_sizes;
                std::size_t                                                 evaluation_points_amount;
                std::map<std::pair<std::size_t, std::size_t>, std::vector<std::size_t>>  eval_map; //(batch_id,poly_id) => point_id

                struct challenges_struct{
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
                        std::size_t  _evaluation_points_amount,
                        const std::map<std::pair<std::size_t, std::size_t>, std::vector<std::size_t>> &_eval_map
                    ){
                        num_gates = poseidon_component_type::get_gate_manifest(witness_amount).get_gates_amount();
                        num_gates += constant_pow_component_type::get_gate_manifest(
                            witness_amount,
                            (field_type::modulus - 1)/fri_params.domain_size
                        ).get_gates_amount();
                        num_gates += x_index_component_type::get_gate_manifest(
                            witness_amount,
                            log2(fri_params.domain_size) - 1
                        ).get_gates_amount();
                    }
                    std::uint32_t gates_amount() const override {
                        return num_gates;
                    }
                };

                static gate_manifest get_gate_manifest(
                    std::size_t witness_amount,
                    const fri_params_type                                            &fri_params,
                    const std::map<std::size_t, std::size_t>                         &batches_sizes,
                    std::size_t                                                      evaluation_points_amount,
                    const std::map<std::pair<std::size_t, std::size_t>, std::vector<std::size_t>> &eval_map
                ) {
                    gate_manifest manifest = gate_manifest(gate_manifest_type(
                        witness_amount,
                        fri_params,
                        batches_sizes,
                        evaluation_points_amount,
                        eval_map
                    ));
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(15)),
                        false
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(
                    std::size_t                                 witness_amount,
                    const fri_params_type                       &_fri_params,
                    const std::map<std::size_t, std::size_t>    &_batches_sizes,
                    std::size_t                                 _evaluation_points_amount,
                    const std::map<std::pair<std::size_t, std::size_t>, std::vector<std::size_t>> &_eval_map
                ) {
                    return 15;
                }

                // Subcomponents list
                poseidon_component_type     poseidon_instance;
                constant_pow_component_type constant_pow_instance;
                x_index_component_type      x_index_instance;

                template <
                    typename WitnessContainerType,
                    typename ConstantContainerType,
                    typename PublicInputContainerType
                >
                plonk_dfri_verifier(
                    WitnessContainerType witnesses,
                    ConstantContainerType constants,
                    PublicInputContainerType public_inputs,
                    const fri_params_type &_fri_params,
                    const std::map<std::size_t, std::size_t> &_batches_sizes,
                    std::size_t  _evaluation_points_amount,
                    const std::map<std::pair<std::size_t, std::size_t>, std::vector<std::size_t>> &_eval_map
                ):  component_type(witnesses, constants, public_inputs, get_manifest()),
                    fri_params(_fri_params),
                    poseidon_instance(witnesses, constants, public_inputs),
                    constant_pow_instance(witnesses, constants, public_inputs, (BlueprintFieldType::modulus - 1)/fri_params.domain_size),
                    x_index_instance(witnesses, constants, public_inputs, log2(fri_params.domain_size) - 1, fri_params.omega),
                    batches_sizes(_batches_sizes),
                    evaluation_points_amount(_evaluation_points_amount),
                    eval_map(_eval_map)
                {
                    rows_amount = get_rows_amount(
                        witnesses.size(),
                        fri_params,
                        batches_sizes,
                        evaluation_points_amount,
                        eval_map
                    );
                }

                std::vector<std::uint32_t> all_witnesses() const{
                    return this->_W;
                }
            };

            template<typename BlueprintFieldType>
            typename plonk_dfri_verifier<BlueprintFieldType>::result_type
            generate_assignments(
                const plonk_dfri_verifier<BlueprintFieldType> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename plonk_dfri_verifier<BlueprintFieldType>::input_type instance_input,
                const std::uint32_t start_row_index
            ) {
                using component_type = plonk_dfri_verifier<BlueprintFieldType>;
                using poseidon_component_type = typename component_type::poseidon_component_type;
                using constant_pow_component_type = typename component_type::constant_pow_component_type;
                using x_index_component_type = typename component_type::x_index_component_type;
                using var = typename component_type::var;

                var zero_var = var(component.C(0), start_row_index, false, var::column_type::constant);
                std::size_t row = start_row_index;

                // Just for testing. Add row computation for each subcomponent.
                std::size_t poseidon_rows = 0;
                std::size_t constant_pow_rows = 0;
                std::size_t swap_rows = 0;

                typename component_type::challenges_struct c;
                typename poseidon_component_type::input_type  poseidon_input; //Used for
                typename poseidon_component_type::result_type poseidon_output;
                const auto &poseidon_instance = component.poseidon_instance;
                const auto &constant_pow_instance = component.constant_pow_instance;
                const auto &x_index_instance = component.x_index_instance;
                const auto &fri_params = component.fri_params;
                poseidon_input.input_state[0] = instance_input.initial_transcript_state;

                // Transcript(commitments)
                for( std::size_t i = 0; i < instance_input.commitments_vector.size()/2; i++){
                    poseidon_input.input_state[1] = instance_input.commitments_vector[i * 2];
                    poseidon_input.input_state[2] = instance_input.commitments_vector[i * 2 + 1];
                    poseidon_output = generate_assignments(poseidon_instance, assignment, poseidon_input, row);
                    poseidon_input.input_state[0] = poseidon_output.output_state[2];
                    row += poseidon_instance.rows_amount;
                    poseidon_rows += poseidon_instance.rows_amount;
                }
                if( instance_input.commitments_vector.size()%2 ){
                    poseidon_input.input_state[1] = instance_input.commitments_vector[instance_input.commitments_vector.size() - 1];
                    poseidon_input.input_state[2] = zero_var;
                    poseidon_output = generate_assignments(poseidon_instance, assignment, poseidon_input, row);
                    poseidon_input.input_state[0] = poseidon_output.output_state[2];
                    row += poseidon_instance.rows_amount;
                    poseidon_rows += poseidon_instance.rows_amount;
                }
                // lpc_theta = transcript.challenge()

                c.lpc_theta = poseidon_output.output_state[2];

                for( std::size_t i = 0; i < fri_params.r; i++){
                    poseidon_input = {poseidon_output.output_state[2], instance_input.fri_roots[i], zero_var};
                    poseidon_output = generate_assignments(poseidon_instance, assignment, poseidon_input, row);
                    c.fri_alphas.push_back(poseidon_output.output_state[2]);
                    row += poseidon_instance.rows_amount;
                    poseidon_rows += poseidon_instance.rows_amount;
                }

                for( std::size_t i = 0; i < fri_params.lambda; i++){
                    poseidon_input = {poseidon_output.output_state[2], zero_var, zero_var};
                    poseidon_output = generate_assignments(poseidon_instance, assignment, poseidon_input, row);
                    c.fri_xs.push_back(poseidon_output.output_state[2]);
                    row += poseidon_instance.rows_amount;
                    poseidon_rows += poseidon_instance.rows_amount;
                }

                std::vector<var> xs;
                for( std::size_t i = 0; i < fri_params.lambda; i++){
                    typename constant_pow_component_type::input_type constant_pow_input = {c.fri_xs[i]};
                    typename constant_pow_component_type::result_type constant_pow_output = generate_assignments(
                        constant_pow_instance, assignment, constant_pow_input, row
                    );
                    xs.push_back(constant_pow_output.y);
                    row+= constant_pow_instance.rows_amount;
                    constant_pow_rows += constant_pow_instance.rows_amount;
                }

                // check correspondence between x, x_index and merkle path
                for( std::size_t i = 0; i < fri_params.lambda; i++){
                    typename x_index_component_type::input_type x_index_input;
                    x_index_input.x = xs[i];
                    for( std::size_t j = 0; j < log2(fri_params.domain_size) - 1; j++){
                        x_index_input.b.push_back(instance_input.merkle_tree_positions[i][j]);
                    }
                    typename x_index_component_type::result_type x_index_output = generate_assignments(
                        x_index_instance, assignment, x_index_input, row
                    );
                    row += x_index_instance.rows_amount;
                }


                const typename component_type::result_type result;
                return result;
            }


            template<typename BlueprintFieldType>
            const typename plonk_dfri_verifier<BlueprintFieldType>::result_type
            generate_circuit(
                const plonk_dfri_verifier<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename plonk_dfri_verifier<BlueprintFieldType>::input_type &instance_input,
                const std::size_t start_row_index
            ) {
                using component_type = plonk_dfri_verifier<BlueprintFieldType>;
                using poseidon_component_type = typename component_type::poseidon_component_type;
                using constant_pow_component_type = typename component_type::constant_pow_component_type;
                using x_index_component_type = typename component_type::x_index_component_type;
                using constraint_type = nil::crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using var = typename component_type::var;

                assignment.constant(0, start_row_index) = 0; //Zero constant
                var zero_var = var(component.C(0), start_row_index, false, var::column_type::constant);
                std::size_t row = start_row_index;

                std::size_t rows = 0;
                std::size_t poseidon_rows = 0;

                typename component_type::challenges_struct c;
                typename poseidon_component_type::input_type  poseidon_input; //Used for
                typename poseidon_component_type::result_type poseidon_output;
                const auto &poseidon_instance = component.poseidon_instance;
                const auto &constant_pow_instance = component.constant_pow_instance;
                const auto &x_index_instance = component.x_index_instance;
                poseidon_input.input_state[0] = instance_input.initial_transcript_state;

                const auto &fri_params = component.fri_params;

                // Transcript(commitments)
                for( std::size_t i = 0; i < instance_input.commitments_vector.size()/2; i++){
                    poseidon_input.input_state[1] = instance_input.commitments_vector[i * 2];
                    poseidon_input.input_state[2] = instance_input.commitments_vector[i * 2 + 1];
                    poseidon_output = generate_circuit(poseidon_instance, bp, assignment, poseidon_input, row);
                    poseidon_input.input_state[0] = poseidon_output.output_state[2];
                    row += poseidon_instance.rows_amount;
                    poseidon_rows += poseidon_instance.rows_amount;
                }
                if( instance_input.commitments_vector.size()%2 ){
                    poseidon_input.input_state[1] = instance_input.commitments_vector[instance_input.commitments_vector.size() - 1];
                    poseidon_input.input_state[2] = zero_var;
                    poseidon_output = generate_circuit(poseidon_instance, bp, assignment, poseidon_input, row);
                    poseidon_input.input_state[0] = poseidon_output.output_state[2];
                    row += poseidon_instance.rows_amount;
                    poseidon_rows += poseidon_instance.rows_amount;
                }
                // lpc_theta = transcript.challenge()
                c.lpc_theta = poseidon_output.output_state[2];

                for( std::size_t i = 0; i < fri_params.r; i++){
                    poseidon_input = {poseidon_output.output_state[2], instance_input.fri_roots[i], zero_var};
                    poseidon_output = generate_circuit(poseidon_instance, bp, assignment, poseidon_input, row);
                    c.fri_alphas.push_back(poseidon_output.output_state[2]);
                    row += poseidon_instance.rows_amount;
                }

                for( std::size_t i = 0; i < fri_params.lambda; i++){
                    poseidon_input = {poseidon_output.output_state[2], zero_var, zero_var};
                    poseidon_output = generate_circuit(poseidon_instance, bp, assignment, poseidon_input, row);
                    c.fri_xs.push_back(poseidon_output.output_state[2]);
                    row += poseidon_instance.rows_amount;
                }

                std::vector<var> xs;
                for( std::size_t i = 0; i < fri_params.lambda; i++){
                    typename constant_pow_component_type::input_type constant_pow_input = {c.fri_xs[i]};
                    typename constant_pow_component_type::result_type constant_pow_output = generate_circuit(
                        constant_pow_instance, bp, assignment, constant_pow_input, row
                    );
                    xs.push_back(constant_pow_output.y);
                    row+= constant_pow_instance.rows_amount;
                }

                for( std::size_t i = 0; i < fri_params.lambda; i++){
                    typename x_index_component_type::input_type x_index_input;
                    x_index_input.x = xs[i];
                    for( std::size_t j = 0; j < log2(fri_params.domain_size) - 1; j++ ){
                        x_index_input.b.push_back(instance_input.merkle_tree_positions[i][j]);
                    }
                    typename x_index_component_type::result_type x_index_output  = generate_circuit(
                        x_index_instance, bp, assignment, x_index_input, row
                    );
                    row += x_index_instance.rows_amount;
                }

                const typename component_type::result_type result;
                return result;
            }
        }
    }
}

#endif
