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
                using value_type = typename BlueprintFieldType::value_type;
                using var = typename component_type::var;

                using poseidon_component_type = plonk_flexible_poseidon<BlueprintFieldType>;
                using swap_component_type = plonk_flexible_swap<BlueprintFieldType>;
                using colinear_checks_component_type = plonk_flexible_colinear_checks<BlueprintFieldType>;
                using constant_pow_component_type = plonk_flexible_constant_pow<BlueprintFieldType>;
                using x_index_component_type = plonk_flexible_x_index<BlueprintFieldType>;
                using dfri_linear_check_component_type = plonk_dfri_linear_check<BlueprintFieldType>;

                std::size_t rows_amount; // calculator, please

                // Internal structure that doesn't depend on commitment scheme types
                // Parts from fri_params that are useful for this component
                struct fri_params_type{
                    std::size_t r;
                    std::size_t lambda;
                    value_type  omega;
                    std::size_t domain_size;
                    std::size_t initial_merkle_proof_size;
                    std::size_t max_degree;
                };
//              TODO: add constants from fixed batches. // TODO: think about them later
//              It just costs a number of copy constraints and constant columns

//              Full component input
                fri_params_type                                             fri_params;
                std::map<std::size_t, std::size_t>                          batches_sizes;
                std::size_t                                                 evaluation_points_amount;
                std::map<std::pair<std::size_t, std::size_t>, std::size_t>  eval_map; //(batch_id,poly_id) => point_id

                struct challenges{
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

                static const std::size_t gates_amount = 0;

                class gate_manifest_type : public component_gate_manifest {
                    std::size_t num_gates;
                public:
                    gate_manifest_type(
                        std::size_t witness_amount,
                        const fri_params_type &_fri_params,
                        const std::map<std::size_t, std::size_t> &_batches_sizes,
                        std::size_t  _evaluation_points_amount,
                        const std::map<std::pair<std::size_t, std::size_t>, std::size_t> &_eval_map
                    ){
                        num_gates = 1;
                    }
                    std::uint32_t gates_amount() const override {
                        std::cout << "Verifier gates_amount " << num_gates << std::endl;
                        return num_gates;
                    }
                };

                static gate_manifest get_gate_manifest(
                    std::size_t witness_amount,
                    const fri_params_type                                            &fri_params,
                    const std::map<std::size_t, std::size_t>                         &batches_sizes,
                    std::size_t                                                      evaluation_points_amount,
                    const std::map<std::pair<std::size_t, std::size_t>, std::size_t> &eval_map
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
                    const std::map<std::pair<std::size_t, std::size_t>, std::size_t> &_eval_map
                ) {
                    return 15;
                }

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
                    const std::map<std::pair<std::size_t, std::size_t>, std::size_t> &_eval_map
                ):  component_type(witnesses, constants, public_inputs, get_manifest()),
                    fri_params(_fri_params),
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

                for(std::size_t i = start_row_index; i < start_row_index + 15; i++){
                    assignment.witness(component.W(0), i) = 0;
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
                std::cout << "Generate circuit" << std::endl;
                using component_type = plonk_dfri_verifier<BlueprintFieldType>;
                using constraint_type = nil::crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using var = typename component_type::var;

                bp.add_gate(var(component.W(0), 0)); // TODO remove this.
                const typename component_type::result_type result;
                return result;
            }
        }
    }
}

#endif
