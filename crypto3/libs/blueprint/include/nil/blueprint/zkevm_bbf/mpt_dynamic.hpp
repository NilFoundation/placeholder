//---------------------------------------------------------------------------//
// Copyright (c) 2025 Alexey Yashunsky <a.yashunsky@nil.foundation>
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

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/bench/scoped_profiler.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>

#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/zkevm_bbf/util.hpp>

#include <nil/blueprint/zkevm_bbf/types/mpt_trie.hpp>
#include <nil/blueprint/zkevm_bbf/mpt_nodes/mpt_branch.hpp>
#include <nil/blueprint/zkevm_bbf/mpt_nodes/mpt_extension.hpp>
#include <nil/blueprint/zkevm_bbf/mpt_nodes/mpt_leaf_proxy.hpp>
#include <nil/blueprint/zkevm_bbf/mpt_nodes/mpt_node_common.hpp>

#include <nil/blueprint/zkevm_bbf/small_field/tables/keccak.hpp>

namespace nil::blueprint::bbf {

template<typename FieldType, GenerationStage stage>
class mpt_dynamic : public generic_component<FieldType, stage> {
    using typename generic_component<FieldType, stage>::context_type;
    using generic_component<FieldType, stage>::allocate;
    using generic_component<FieldType, stage>::copy_constrain;
    using generic_component<FieldType, stage>::constrain;
    using generic_component<FieldType, stage>::lookup;
    using generic_component<FieldType, stage>::lookup_table;
    using generic_component<FieldType, stage>::multi_lookup_table;

public:
    using typename generic_component<FieldType, stage>::table_params;
    using typename generic_component<FieldType, stage>::TYPE;

    using input_nodes = typename std::conditional<stage==GenerationStage::ASSIGNMENT, mpt_nodes_vector, std::nullptr_t>::type;
    using input_root = typename std::conditional<stage==GenerationStage::ASSIGNMENT, zkevm_word_type, std::nullptr_t>::type;

    struct input_type {
        TYPE rlc_challenge;

        input_nodes nodes_vector;
        input_root root;
    };

    using value_type = typename FieldType::value_type;
    using integral_type = nil::crypto3::multiprecision::big_uint<257>;

    static table_params get_minimal_requirements(std::size_t max_mpt_size) {
        return {
            .witnesses = 1 // rlc_challenge copy column
                + mpt_node_common<FieldType, stage>::get_witness_amount() // the common columns for all node types
                + std::max({mpt_branch<FieldType, stage>::get_witness_amount(), // maximum of needed columns
                         mpt_extension<FieldType, stage>::get_witness_amount(),
                         mpt_leaf_proxy<FieldType, stage>::get_witness_amount()})
                + zkevm_small_field::keccak_table<FieldType,stage>::get_witness_amount(), // keccak table
            .public_inputs = 1,
            .constants = 0,
            .rows = max_mpt_size
        };
    }

    static void allocate_public_inputs(
            context_type &context, input_type &input,
            std::size_t max_mpt_size) {
        context.allocate(input.rlc_challenge, 0, 0, column_type::public_input);
    }

    std::size_t get_column(const TYPE &V) {
        std::size_t res = 0;
        if constexpr (stage == GenerationStage::CONSTRAINTS) {
            using var = context<FieldType, stage>::var;
            auto is_var = nil::crypto3::zk::snark::expression_is_variable_visitor<var>::is_var;
            BOOST_ASSERT(is_var(V));
            var V_var = boost::get<crypto3::zk::snark::term<var>>(V.get_expr()).get_vars()[0];
            res = V_var.index;
        } else {
            throw std::runtime_error("get_column function used at assignment stage.");
        }
        return res;
    }

    mpt_dynamic(context_type &context_object,
        const input_type &input,
        std::size_t max_mpt_size) : generic_component<FieldType,stage>(context_object) {

        // Table columns, listed by order of allocation into the table
        std::vector<TYPE> rlc_challenge(max_mpt_size);     // copies of RLC challenge from public input

        // Columns for storing information common to all node types
        std::size_t cur_column = 1;
        std::vector<std::size_t> node_common_columns;
        for(std::size_t i = 0; i < mpt_node_common<FieldType, stage>::get_witness_amount(); i++, cur_column++) {
            node_common_columns.push_back(cur_column);
        }

        // All other columns are delegated to node-specific subcomponents. For them we'll create subcontexts
        std::vector<std::size_t> node_specific_columns;
        std::size_t num_of_node_specific_columns = std::max({mpt_branch<FieldType, stage>::get_witness_amount(),
                         mpt_extension<FieldType, stage>::get_witness_amount(),
                         mpt_leaf_proxy<FieldType, stage>::get_witness_amount()});

        for(std::size_t i = 0; i < num_of_node_specific_columns; i++, cur_column++) {
            node_specific_columns.push_back(cur_column);
        }

        // The last columns are for Keccak lookup table
        std::vector<std::size_t> keccak_columns;
        for(std::size_t i = 0; i < zkevm_small_field::keccak_table<FieldType,stage>::get_witness_amount(); i++, cur_column++) {
            keccak_columns.push_back(cur_column);
        }

        // Now prepare a list of nodes to be processed (compatible with both assignment and constraints stages)
        // For the assignment stage we convert a list of paths into a unified list of nodes,
        // appending the additional "subtree" nodes.
        std::unordered_map<mpt_node_id, mpt_node> deploy_plan;

        if constexpr (stage == GenerationStage::ASSIGNMENT) {
            std::size_t trie_id = 1; // TODO : adjust later

            struct node_temporary_holder {
                std::size_t accumulated_key_len;
                zkevm_word_type accumulated_key;
                bool is_extension;
                std::size_t key_len;
            };

            std::map<zkevm_word_type, node_temporary_holder> parents;
            parents.insert(std::pair<zkevm_word_type, node_temporary_holder> (input.root, {
                0, 0, false, 0
            }));
            for(auto &node : input.nodes_vector) { // enumerate nodes
                node_temporary_holder parent = parents.at(node.hash);
                if (node.type == branch) {
                    for (size_t i = 0; i < 16; i++) {
                        if (node.value[i] != 0) {
                            parents.insert(std::pair<zkevm_word_type, node_temporary_holder> (
                                node.value[i], {
                                    parent.accumulated_key_len + 1,
                                    (parent.accumulated_key << 4) + i,
                                    false,
                                    1
                                }
                            ));
                        }
                    }
                } else if (node.type == extension)  {
                    zkevm_word_type k0 = node.value[0] >> (node.len.at(0) - 1)*4;
                    std::size_t accumulated_key_length;
                    zkevm_word_type accumulated_key;
                    std::size_t key_extension_length;
                    zkevm_word_type key_extension;
                    
                    BOOST_ASSERT_MSG(k0 == 1 || k0 == 0, "Wrong extension node format!");
                    if (k0 == 0)
                        key_extension_length = node.len[0] - 2;
                    else
                        key_extension_length = node.len[0] - 1;
                    key_extension = node.value[0] - (k0 << key_extension_length * 4);
                    parents.insert(std::pair<zkevm_word_type, node_temporary_holder> (
                        node.value[1], {
                            parent.accumulated_key_len + key_extension_length,
                            (parent.accumulated_key << 4 * key_extension_length) + key_extension,
                            true,
                            key_extension_length
                        }
                    ));
                }
                BOOST_LOG_TRIVIAL(info) << "node added:\n";
                
                BOOST_LOG_TRIVIAL(info) << "\thash:\t\t\t" << std::hex << node.hash << std::dec << std::endl;
                BOOST_LOG_TRIVIAL(info) << "\taccumulated_key:\t" << std::hex << parent.accumulated_key << std::dec << std::endl;
                BOOST_LOG_TRIVIAL(info) << "\taccumulated_key_len:\t" << std::hex << parent.accumulated_key_len << std::dec << std::endl;
                BOOST_LOG_TRIVIAL(info) << "\tkey_len:\t\t" << std::hex << parent.key_len << std::dec << std::endl;
                BOOST_LOG_TRIVIAL(info) << "\ttype:\t\t\t" << std::hex << node.type << std::dec << std::endl;
                BOOST_LOG_TRIVIAL(info) << "\tis_extension:\t\t" << std::hex << parent.is_extension << std::dec << std::endl;

                mpt_node_id n_id = { trie_id, parent.accumulated_key, parent.accumulated_key_len, parent.key_len, node.type, parent.is_extension };

                if (deploy_plan.find(n_id) != deploy_plan.end()) {
                    // TODO process node _replacement_
                    std::cout << "We have a replacement" << std::endl;
                    BOOST_ASSERT(0); // When we encounter such a situation, we need code here
                } else {
                    deploy_plan[n_id] = node;
                }
                // }
            }
        } else {
           for(std::size_t virtual_node = 0; virtual_node < NODE_TYPE_COUNT; virtual_node++) {
               mpt_node_id n_id = {
                   .trie_id = 0,
                   .accumulated_key = 0,
                   .accumulated_key_length = 0,
                   .parent_key_length = 0,
                   .type = mpt_node_type(virtual_node)
               };
               deploy_plan[n_id] = mpt_node({mpt_node_type(virtual_node), {0}, {0}});
           }
        }
        // at this point deploy_plan contains all the information we need

        // a place to store all the sequences that are to be hashed via keccak
        typename zkevm_small_field::keccak_table<FieldType,stage>::private_input_type keccak_buffers;
        // we need the hash of an empty string as a fallback for some lookups
        static const auto zerohash = w_to_16(zkevm_keccak_hash({}));

        // prepare the RLC column (independent of everything else)
        for(std::size_t i = 0; i < max_mpt_size; i++) {
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                rlc_challenge[i] = input.rlc_challenge; // all challenges are equal :)
            }
            allocate(rlc_challenge[i], 0, i);
            copy_constrain(input.rlc_challenge, rlc_challenge[i]);
        }

        // the main cycle (Assignments & constraints)
        std::size_t node_num = 0; // = row number, since we have 1 row per node
        for(auto nr : deploy_plan) {
            mpt_node_id n_id = nr.first;
            mpt_node n = nr.second;
            // std::cout << "\nnode " << node_num << " type = " << n.type << std::endl;

            // allocate first part of row for common information
            context_type common_row_context = context_object.fresh_subcontext(node_common_columns, node_num, 1);
            typename mpt_node_common<FieldType, stage>::input_type common_input;
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                common_input = n_id;
            }
            auto Res = mpt_node_common<FieldType, stage>(common_row_context, common_input);

            if constexpr (stage == GenerationStage::CONSTRAINTS) {
                TYPE padding;
                for(std::size_t type_index = 0; type_index < NODE_TYPE_COUNT; type_index++) {
                    TYPE type_selector = context_object.relativize(Res.type_selector[type_index], -node_num);
                    context_object.relative_constrain( type_selector * (1 - type_selector), 0, max_mpt_size - 1);
                    padding += type_selector;
                }
                context_object.relative_constrain( padding * (padding - 1), 0, max_mpt_size - 1);

                auto row_constraints = common_row_context.get_constraints();
                for (const auto &constr_list: row_constraints) {
                     BOOST_ASSERT(constr_list.first.size() == 1); // there should only be one row in the subcomponent
                     for (auto [constraint, name]: constr_list.second) {
                         context_object.relative_constrain(constraint * padding, 0, max_mpt_size - 1, name);
                     }
                }
                // NB: if there are range-check lookups, we should define them externally
            }

            // allocate second part of row for node-specific information
            context_type node_row_context = context_object.fresh_subcontext(node_specific_columns, node_num, 1);

            // preparing input for the subcomponents
            node_private_input<FieldType, stage> node_data;
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                // actual node data is only available at assignment stage
                node_data = n;
            }

            mpt_node_input_type<FieldType, stage> node_input = {
                .rlc_challenge = rlc_challenge[node_num],

                .node_accumulated_key = Res.accumulated_key,
                .node_last_nibble = Res.last_nibble,
                .node_nibble_present = Res.nibble_present,

                .node_data = node_data,
                .keccak_buffers = &keccak_buffers
            };

            std::array<TYPE, 32> parent_hash; // allocated by node-specific code
            std::array<std::array<TYPE, 32>, 16> child; // 16 32-byte child hashes for branch nodes

            std::array<TYPE, 32> child_accumulated_key;
            TYPE child_nibble_present;
            TYPE ext_child_last_nibble;
            std::array<TYPE, 16> child_last_nibble;
            std::array<TYPE, 15> child_accumulated_key_last_byte;

            std::array<TYPE, 32> ext_value; // allocated by extension nodes

            if (n.type == branch) {
                auto res = mpt_branch(node_row_context, node_input);
                parent_hash = res.parent_hash;
                child = res.child;

                child_accumulated_key = res.child_accumulated_key;
                child_nibble_present = res.child_nibble_present;
                child_last_nibble = res.child_last_nibble;
                child_accumulated_key_last_byte = res.child_accumulated_key_last_byte;



                if constexpr (stage == GenerationStage::ASSIGNMENT) {
                    std::stringstream ss;
                    ss << "selector: " << Res.type_selector[branch] << std::endl;
                    ss << "trie_id: " << Res.trie_id << std::endl;
                    ss << "child nibble present: " << child_nibble_present << std::endl;
                    ss << "child accumulated key: ";
                    for(std::size_t i = 0; i < 31; i++)
                        ss << std::hex << child_accumulated_key[i] << std::dec << " ";
                    ss << "\n";
                    for(std::size_t j = 0; j < 16; j++) {
                    ss << "last byte: " << std::hex << (j > 0 ? child_accumulated_key_last_byte[j-1] :
                                                                child_accumulated_key[31]) << std::dec << std::endl;
                        ss << "child last nibble: " << std::hex << child_last_nibble[j] << std::dec << "\n";
                        ss << "accumulated key length: " << std::hex << Res.accumulated_key_length << std::dec << "\n";
                        ss << "child: ";
                        for(std::size_t i = 0; i < 32; i++) {
                            if (static_cast<std::uint8_t>(child[j][i].to_integral()) < 0x10)
                                ss << "0";
                            ss << std::hex << child[j][i] << std::dec;
                        }
                        ss << std::endl;
                    }
                    ss << "starting:\n";

                    for(std::size_t j = 0; j < 16; j++) {
                        ss << std::hex << Res.type_selector[branch] << std::dec << " ";
                        ss << std::hex << Res.trie_id << std::dec << " ";
                        ss << std::hex << child_nibble_present << std::dec << " ";
                        for(std::size_t i = 0; i < 31; i++) {
                            ss << std::hex << child_accumulated_key[i] << std::dec << " ";
                        }

                        ss << std::hex << (j > 0 ? child_accumulated_key_last_byte[j-1] :
                            child_accumulated_key[31]) << std::dec << " ";
                        ss << std::hex << child_last_nibble[j] << std::dec << " ";
                        ss << std::hex << Res.accumulated_key_length << std::dec << " ";

                        for(std::size_t i = 0; i < 32; i++) {
                            ss << std::hex << child[j][i] << std::dec << " ";
                        }
                        ss << std::endl;
                    }
                    BOOST_LOG_TRIVIAL(trace) << ss.str();

                }
                // 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 8c 0 1 51 cd d8 ba d1 17 16 2a cf c2 5a 3b a5 11 3 97 e4 96 4f 78 f6 53 f8 d0 aa da 88 ed dc d2 1f b7 
                // 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0  1 51 cd d8 ba d1 17 16 2a cf c2 5a 3b a5 11 3 97 e4 96 4f 78 f6 53 f8 d0 aa da 88 ed dc d2 1f b7 
            } else if (n.type == extension) {
                auto res = mpt_extension(node_row_context, node_input);
                parent_hash = res.parent_hash;
                child_accumulated_key = res.child_accumulated_key;
                child_nibble_present = res.child_nibble_present;
                ext_child_last_nibble = res.child_last_nibble;
                ext_value = res.ext_value;
            } else if (n.type == leaf) {
                parent_hash = mpt_leaf_proxy(node_row_context, node_input).parent_hash;
            }

            if constexpr (stage == GenerationStage::CONSTRAINTS) {
                auto selector = context_object.relativize(Res.type_selector[static_cast<std::size_t>(n.type)], -node_num);

                auto row_constraints = node_row_context.get_constraints();
                for (const auto &constr_list: row_constraints) {
                    BOOST_ASSERT(constr_list.first.size() == 1); // there should only be one row in the subcomponent
                    for (auto [constraint, name]: constr_list.second) {
                        context_object.relative_constrain(constraint * selector, 0, max_mpt_size - 1, name);
                    }
                }
                auto row_lookup_constraints = node_row_context.get_lookup_constraints();
                for (const auto &constr_list: row_lookup_constraints) {
                    BOOST_ASSERT(constr_list.first.size() == 1); // there should only be one row in the subcomponent
                    for (auto lookup_constraint: constr_list.second) {
                        auto exprs = lookup_constraint.second;
                        if (lookup_constraint.first != "keccak_table") {
                            for(auto &e : exprs) {
                                e *= selector;
                            }
                        } else {
                            exprs[0] *= selector;
                            for(std::size_t i = 0; i < 16; i++) {
                                exprs[i+1] = exprs[i+1]*selector + (1 - selector)*zerohash[i];
                            }
                        }
                        context_object.relative_lookup(exprs, lookup_constraint.first, 0, max_mpt_size - 1);
                    }
                }

                // unified key_to_child_hash lookup table:
                // (branch_selector,trie_id,
                //  child_nibble_present,child_accumulated_key,child_last_nibble, parent_accumulated_key_length,
                //  hash)
                //
                // NB: branch_selector == 1 => meaningful information, branch_selector == 0 => junk
                // NB: to work correctly we need at least one row with zeroes everywhere
                if (n.type == branch) {
                    std::vector<std::vector<std::size_t>> options;
                    std::vector<std::size_t> common_option_header = {
                            get_column(Res.type_selector[branch]),
                            get_column(Res.trie_id)
                    };
                    common_option_header.push_back(get_column(child_nibble_present));

                    for(std::size_t i = 0; i < 31; i++) {
                        common_option_header.push_back(get_column(child_accumulated_key[i]));
                    }
                    for(std::size_t j = 0; j < 16; j++) {
                        options.push_back(common_option_header);
                        options[j].push_back(get_column(j > 0 ? child_accumulated_key_last_byte[j-1] :
                                                                child_accumulated_key[31]));
                        options[j].push_back(get_column(child_last_nibble[j]));
                        options[j].push_back(get_column(Res.accumulated_key_length));
                        for(std::size_t i = 0; i < 32; i++) {
                            options[j].push_back(get_column(child[j][i]));
                        }

                    }
                    multi_lookup_table("key_to_child_hash", options, 0, max_mpt_size);
                }

                if (n.type == extension) {
                    std::vector<std::size_t> k2ext_lookup_columns = {
                            get_column(Res.type_selector[extension]),
                            get_column(Res.trie_id)
                    };
                    k2ext_lookup_columns.push_back(get_column(child_nibble_present));
                    for(std::size_t i = 0; i < 32; i++) {
                        k2ext_lookup_columns.push_back(get_column(child_accumulated_key[i]));
                    }
                    k2ext_lookup_columns.push_back(get_column(ext_child_last_nibble));
                    k2ext_lookup_columns.push_back(get_column(Res.accumulated_key_length));
                    for(std::size_t i = 0; i < 32; i++) {
                        k2ext_lookup_columns.push_back(get_column(ext_value[i]));
                    }
                    lookup_table("key_to_ext_hash", k2ext_lookup_columns, 0, max_mpt_size);
                }

                // Inter-row connections: any node type can have a branch node as parent.
                // Hence we define here conditional lookups to child_hash tables
                TYPE padding;
                for(std::size_t type_index = 0; type_index < NODE_TYPE_COUNT; type_index++) {
                    padding += Res.type_selector[type_index];
                }
                // queries from branch children to its parent via unified key_to_child_hash lookup table
                std::vector<TYPE> query = {
                    padding * Res.parent_is_branch,
                    padding * Res.trie_id * Res.parent_is_branch
                };
                query.push_back(padding * Res.nibble_present * Res.parent_is_branch);

                for(std::size_t i = 0; i < 32; i++) {
                    query.push_back(padding * Res.accumulated_key[i] * Res.parent_is_branch); // the node's accumulated_key
                }

                query.push_back(padding * Res.last_nibble * Res.parent_is_branch);
                query.push_back(padding * (Res.accumulated_key_length - 1) * Res.parent_is_branch); // parent's accumulated_key length
                for(std::size_t i = 0; i < 32; i++) {
                    query.push_back(padding * parent_hash[i] * Res.parent_is_branch); // the hash bytes to check against parent
                }

                for(auto &e : query) {
                    e = context_object.relativize(e, -node_num);
                }
                context_object.relative_lookup(query, "key_to_child_hash", 0, max_mpt_size - 1);

                // query extension node value:
                query = {
                    padding * Res.parent_is_ext,
                    padding * Res.trie_id * Res.parent_is_ext
                };
                query.push_back(padding * Res.nibble_present * Res.parent_is_ext);
                for(std::size_t i = 0; i < 32; i++) {
                    query.push_back(padding * Res.accumulated_key[i] * Res.parent_is_ext); // the node's accumulated_key
                }
                query.push_back(padding * Res.last_nibble * Res.parent_is_ext);
                // parent's accumulated_key length
                query.push_back(padding * (Res.accumulated_key_length - Res.parent_key_length) * Res.parent_is_ext);
                for(std::size_t i = 0; i < 32; i++) {
                    query.push_back(padding * parent_hash[i] * Res.parent_is_ext); // the parent hash bytes
                }
                for(auto &e : query) {
                    e = context_object.relativize(e, -node_num);
                }
                context_object.relative_lookup(query, "key_to_ext_hash", 0, max_mpt_size - 1);
            }

            node_num++;
        }
        context_type keccak_ct = context_object.subcontext(keccak_columns, 0, max_mpt_size);
        zkevm_small_field::keccak_table<FieldType,stage>(keccak_ct, {input.rlc_challenge, keccak_buffers}, max_mpt_size);
        // TODO: last parameter ^^^ should be max_keccak_blocks, but for now max_mpt_size is ok
    }
};
} // namespace nil::blueprint::bbf
