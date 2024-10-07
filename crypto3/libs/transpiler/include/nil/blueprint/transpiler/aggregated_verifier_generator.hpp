//---------------------------------------------------------------------------//
// Copyright (c) 2023 Elena Tatuzova <e.tatuzova@nil.foundation>
// Copyright (c) 2024 Dmitrii Tabalin <d.tabalin@nii.foundation>
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

#include <sstream>
#include <map>

#include <boost/algorithm/string/replace.hpp>
#include <nil/blueprint/transpiler/util.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/hash/sha2.hpp>

#include<nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/zk/math/expression.hpp>
#include <nil/crypto3/zk/math/expression_visitors.hpp>
#include <nil/crypto3/zk/math/expression_evaluator.hpp>

#include <nil/blueprint/transpiler/templates/recursive_verifier.hpp>
#include <nil/blueprint/transpiler/util.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/profiling.hpp>

namespace nil {
    namespace blueprint {
        template<typename PlaceholderParams, typename AggregatedProofType>
        struct aggregated_verifier_generator {
            using field_type = typename PlaceholderParams::field_type;
            using proof_type = AggregatedProofType;
            using commitment_scheme_type = typename PlaceholderParams::commitment_scheme_type;
            using constraint_system_type = typename PlaceholderParams::constraint_system_type;
            using columns_rotations_type = std::vector<std::set<int>>;
            using variable_type = typename constraint_system_type::variable_type;
            using variable_indices_type = std::map<variable_type, std::size_t>;
            using degree_visitor_type = typename constraint_system_type::degree_visitor_type;
            using expression_type = typename constraint_system_type::expression_type;
            using term_type = typename constraint_system_type::term_type;
            using binary_operation_type = typename constraint_system_type::binary_operation_type;
            using pow_operation_type = typename constraint_system_type::pow_operation_type;
            using assignment_table_type = typename PlaceholderParams::assignment_table_type;

            static std::string generate_field_array2_from_64_hex_string(std::string str){
                BOOST_ASSERT_MSG(str.size() == 64, "input string must be 64 hex characters long");
                std::string first_half = str.substr(0, 32);
                std::string second_half = str.substr(32, 32);
                return  "{\"vector\": [{\"field\": \"0x" + first_half + "\"},{\"field\": \"0x" + second_half + "\"}]}";
            }

            template<typename HashType>
            static inline std::string generate_hash(typename HashType::digest_type hashed_data){
                if constexpr(std::is_same<HashType, nil::crypto3::hashes::sha2<256>>::value){
                    std::stringstream out;
                    out << hashed_data;
                    return generate_field_array2_from_64_hex_string(out.str());
                } else if constexpr(std::is_same<HashType, nil::crypto3::hashes::keccak_1600<256>>::value){
                    std::stringstream out;
                    out << hashed_data;
                    return generate_field_array2_from_64_hex_string(out.str());
                } else {
                    std::stringstream out;
                    out << "{\"field\": \"" <<  hashed_data <<  "\"}";
                    return out.str();
                }
                BOOST_ASSERT_MSG(false, "unsupported merkle hash type");
                return "unsupported merkle hash type";
            }

            template<typename CommitmentSchemeType>
            static inline std::string generate_commitment(typename CommitmentSchemeType::commitment_type commitment) {
                return generate_hash<typename CommitmentSchemeType::lpc::merkle_hash_type>(commitment);
            }

            inline std::string generate_input(
                const typename assignment_table_type::public_input_container_type &public_inputs,
                const proof_type &proof,
                const std::vector<std::size_t> public_input_sizes
            ){
                BOOST_ASSERT(public_input_sizes.size() == desc.public_input_columns);
                std::stringstream out;
                out << "[" << std::endl;
                // public inputs
                if (desc.public_input_columns != 0) {
                    out << "\t{\"array\":[" << std::endl;
                    bool after_first = 0;
                    for (std::size_t i = 0; i < desc.public_input_columns; i++) {
                        std::size_t max_non_zero = 0;
                        for (auto rit = public_inputs[i].rbegin(); rit != public_inputs[i].rend(); ++rit) {
                            if (*rit != 0) { [[unlikely]]
                                max_non_zero = std::distance(rit, public_inputs[i].rend()) - 1;
                                break;
                            }
                        }
                        if (max_non_zero + 1 > public_input_sizes[i]) {
                            std::cout << "Public input size is larger than reserved. Real size = "
                                      << max_non_zero  + 1 << " reserved = " << public_input_sizes[i] << std::endl;
                            exit(1);
                        }
                        BOOST_ASSERT(max_non_zero <= public_input_sizes[i]);
                        std::size_t j = 0;
                        for (; j < public_inputs[i].size(); j++, after_first = true) {
                            if (after_first) [[likely]] out << "," << std::endl;
                            out << "\t\t{\"field\": \"" << public_inputs[i][j] << "\"}";
                        }
                        for (; j < public_input_sizes[i]; j++, after_first = true) {
                            if (after_first) [[likely]] out << "," << std::endl;
                            out << "\t\t{\"field\": \"" << typename field_type::value_type(0) << "\"}";
                        }
                    }
                    out << std::endl << "\t]}," << std::endl;
                }
                // commitments for each partial proof
                // aka std::vector<placeholder_partial_proof<FieldType, ParamsType>> partial_proofs;
                for (auto const &partial_proof : proof.partial_proofs) {
                    out << "\t{\"struct\":[" << std::endl;
                    out << "\t\t{\"array\":[" << std::endl;
                    bool after_first = false;
                    for (const auto &[index, commitment]: partial_proof.commitments) {
                        if (after_first) [[likely]] out << "," << std::endl;
                        out << "\t\t\t"
                            << generate_commitment<typename PlaceholderParams::commitment_scheme_type>(commitment);
                        after_first = true;
                    }
                    out << "\t\t]}]}," << std::endl;
                }
                // aggregated proof type
                const auto &aggregated_proof = proof.aggregated_proof;
                out << "\t{\"struct\":[" << std::endl;
                // single fri proof checking that F(x) is low degree

                // basic_fri::round_proofs_batch_type fri_round_proof
                const auto &fri_round_proof = aggregated_proof.fri_proof;
                // which is in essence std::vector<std::vector<round_proof_type>> round_proofs;
                out << "\t\t{\"array\":[" << std::endl;
                bool after_first = false;
                for (const auto &outer_proof_vector : fri_round_proof.fri_round_proof.round_proofs) {
                    if (after_first) [[likely]] out << "," << std::endl;
                    out << "\t\t\t{\"array\":[" << std::endl;
                    bool after_first_inner = false;
                    for (const auto &round_proof : outer_proof_vector) {
                        if (after_first_inner) [[likely]] out << "," << std::endl;
                        BOOST_ASSERT_MSG(round_proof.y.size() == 1, "Unsupported step_list value");
                        out << "\t\t\t\t{\"array\":[" << std::endl;
                        out << "\t\t\t\t\t{\"field\":\"" << round_proof.y[0][0] << "\"}," << std::endl;
                        out << "\t\t\t\t\t{\"field\":\"" << round_proof.y[0][1] << "\"}";
                        out << std::endl << "\t\t\t\t]}";
                        after_first_inner = true;
                    }
                    out << "\t\t\t]}," << std::endl;
                    // serialize only hashes, as all paths are the same
                    const auto &merkle_proof_path = outer_proof_vector.begin()->p.path();
                    out << "\t\t\t{\"array\":[" << std::endl;
                    bool path_after_first = false;
                    for (const auto &path_elem : merkle_proof_path) {
                        if (path_after_first) [[likely]] out << "," << std::endl;
                        out << "\t\t\t\t" << generate_hash<typename commitment_scheme_type::lpc::merkle_hash_type>(
                            path_elem[0].hash()
                        );
                        path_after_first = true;
                    }
                    out << std::endl << "\t\t\t]}";
                    after_first = true;
                }
                out << "\t]}]}," << std::endl;
                // typename basic_fri::commitments_part_of_proof fri_commitments_proof_part;
                // consisting of std::vector<commitment_type> fri_roots;
                auto &fri_commitments_proof_part = fri_round_proof.fri_commitments_proof_part;
                out << "\t\t{\"array\":[" << std::endl;
                after_first = false;
                for (const auto &fri_root : fri_commitments_proof_part.fri_roots) {
                    if (after_first) [[likely]] out << "," << std::endl;
                    out << "\t\t\t" << generate_commitment<typename PlaceholderParams::commitment_scheme_type>(
                        fri_root);
                    after_first = true;
                }
                out << std::endl << "\t\t]}," << std::endl;
                // and math::polynomial<typename field_type::value_type> final_polynomial;
                after_first = false;
                const auto &final_polynomial = fri_commitments_proof_part.final_polynomial;
                out << "\t\t{\"array\":[" << std::endl;
                for (std::size_t i = 0; i < final_polynomial.size(); i++) {
                    if (after_first) [[likely]] out << "," << std::endl;
                    out << "\t\t\t{\"field\": \"" << final_polynomial[i] << "\"}";
                    after_first = true;
                }
                out << std::endl << "\t\t]}," << std::endl;

                // std::vector<lpc_proof_type> initial_proofs_per_prover;
                out << "\t\t{\"array\":[" << std::endl;
                after_first = false;
                for (const auto &lpc_proof : aggregated_proof.initial_proofs_per_prover) {
                    if (after_first) [[likely]] out << "," << std::endl;
                    // eval_storage_type z;
                    out << "\t\t\t{\"array\":[" << std::endl;
                    const auto &eval_storage = lpc_proof.z;
                    const auto &batch_info = eval_storage.get_batch_info();
                    std::size_t sum = 0;
                    for (const auto& [k, v] : batch_info) {
                        for (std::size_t i = 0; i < v; i++) {
                            BOOST_ASSERT(eval_storage.get_poly_points_number(k, i) != 0);
                            for(std::size_t j = 0; j < eval_storage.get_poly_points_number(k, i); j++){
                                if( sum != 0 ) out << "," << std::endl;
                                out << "\t\t\t\t{\"field\":\"" << eval_storage.get(k, i, j) << "\"}";
                                sum++;
                            }
                        }
                    }
                    out << std::endl << "\t\t]}," << std::endl;
                    // and basic_fri::initial_proofs_batch_type initial_fri_proofs;
                    // which is std::vector<std::map<std::size_t, initial_proof_type>> initial_proofs;
                    const auto &initial_proofs = lpc_proof.initial_fri_proofs.initial_proofs;
                    out << "\t\t{\"array\":[" << std::endl;
                    bool map_after_first = false;
                    for (const auto &initial_proofs_map : initial_proofs) {
                        if (map_after_first) [[likely]] out << "," << std::endl;
                        out << "\t\t\t{\"struct\":[" << std::endl;
                        bool inner_after_first = false;
                        for (const auto &[index, value] : initial_proofs_map) {
                            if (inner_after_first) [[likely]] out << "," << std::endl;
                            // each initial proof is polynomials_values_type values;
                            // which is std::vector<std::vector<std::array<value_type, FRI::m>>>
                            // and merkle_proof_type p;
                            const auto &values = value.values;
                            for (const auto &outer_vector : values) {
                                out << "\t\t\t\t{\"array\":[" << std::endl;
                                bool core_after_first = false;
                                for (const auto &inner_vector : outer_vector) {
                                    if (core_after_first) [[likely]] out << "," << std::endl;
                                    out << "\t\t\t\t\t{\"array\":[" << std::endl;
                                    bool array_after_first = false;
                                    for (const auto &elem : inner_vector) {
                                        if (array_after_first) [[likely]] out << "," << std::endl;
                                        out << "\t\t\t\t\t\t{\"field\":\"" << elem << "\"}";
                                        array_after_first = true;
                                    }
                                    out << std::endl << "\t\t\t\t\t]}";
                                    core_after_first = true;
                                }
                                out << std::endl << "\t\t\t\t]},";
                            }
                            // serialize only hashes, as all paths are the same
                            const auto &merkle_proof_path = initial_proofs_map.begin()->second.p.path();
                            out << "\t\t\t\t{\"array\":[" << std::endl;
                            bool path_after_first = false;
                            for (const auto &path_elem : merkle_proof_path) {
                                if (path_after_first) [[likely]] out << "," << std::endl;
                                out << "\t\t\t\t\t" << generate_hash<typename commitment_scheme_type::lpc::merkle_hash_type>(
                                    path_elem[0].hash()
                                );
                                path_after_first = true;
                            }
                            out << std::endl << "\t\t\t\t]}";
                            inner_after_first = true;
                        }
                        out << "\t\t\t]}" << std::endl;
                        map_after_first = true;
                    }
                    out << "\t\t]}" << std::endl;
                    after_first = true;
                }
                out << "\t\t]}," << std::endl;
                // and now serialize one of the merkle proof paths
                // all of them should be the same
                const auto &merkle_proof_path =
                    aggregated_proof.initial_proofs_per_prover.begin()->initial_fri_proofs.initial_proofs.begin()->begin()->second.p.path();
                out << "\t\t{\"array\":[" << std::endl;
                after_first = false;
                for (const auto &path_elem : merkle_proof_path) {
                    if (after_first) [[likely]] out << "," << std::endl;
                    out << "\t\t\t\t" << generate_hash<typename commitment_scheme_type::lpc::merkle_hash_type>(
                        path_elem[0].position()
                    );
                    after_first = true;
                }
                out << std::endl << "\t\t]}," << std::endl;
                // typename LPCParams::grinding_type::output_type proof_of_work;
                out << "\t{\"field\":\"" << aggregated_proof.proof_of_work << "\"}" << std::endl;
                out << "]" << std::endl;
                return out.str();
            }

            aggregated_verifier_generator(
                zk::snark::plonk_table_description<typename PlaceholderParams::field_type> _desc) : desc(_desc) {}

            private:
                const zk::snark::plonk_table_description<typename PlaceholderParams::field_type> desc;
        };
    }   // namespace blueprint
}   // namespace nil