//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova   <e.tatuzova@nil.foundation>
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
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

#ifndef CRYPTO3_BLUEPRINT_BBF_KECCAK_TABLE_HPP
#define CRYPTO3_BLUEPRINT_BBF_KECCAK_TABLE_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>
// #include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/lookup_library.hpp>

#include <nil/blueprint/components/hashes/sha2/plonk/detail/split_functions.hpp>
#include <nil/blueprint/components/hashes/keccak/util.hpp>
//#include <nil/blueprint/components/hashes/keccak/keccak_round.hpp>

#include <nil/crypto3/hash/type_traits.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/blueprint/bbf/generic.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            template <typename BlueprintFieldType>
            std::pair<typename BlueprintFieldType::value_type, typename BlueprintFieldType::value_type>
            keccak_component_hash(const std::vector<uint8_t> &buffer){
                using value_type = typename BlueprintFieldType::value_type;
                nil::crypto3::hashes::keccak_1600<256>::digest_type d = nil::crypto3::hash<nil::crypto3::hashes::keccak_1600<256>>(buffer);
                nil::crypto3::algebra::fields::field<256>::integral_type n(d);
                std::pair<value_type, value_type> hash_value;

                hash_value.first = (n & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000_cppui_modular257) >> 128;
                hash_value.second = n & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_cppui_modular257;
                return hash_value;
            }

            template<typename BlueprintFieldType>
            class keccak_table_input_type {
                public:
                using data_item = std::pair<std::vector<std::uint8_t>,
                        std::pair<typename BlueprintFieldType::value_type, typename BlueprintFieldType::value_type>>;
                using data_type = std::vector<data_item>;

                void fill_data(const data_type& _input){
                    input = _input;
                }

                void new_buffer(const data_item &_pair){
                    input.push_back(_pair);
                }

                void new_buffer(const std::vector<std::uint8_t> buffer){
                    input.push_back({buffer, keccak_component_hash<BlueprintFieldType>(buffer)});
                }

                data_type input;
            };


            // Component for keccak table

            template<typename FieldType, GenerationStage stage>
            class keccak_table : public generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;

                public:
                using typename generic_component<FieldType,stage>::TYPE;

                std::size_t max_blocks;

                std::vector<TYPE> is_last = std::vector<TYPE>(max_blocks);
                std::vector<TYPE> hash_hi = std::vector<TYPE>(max_blocks);
                std::vector<TYPE> hash_lo = std::vector<TYPE>(max_blocks);
                std::vector<TYPE> RLC = std::vector<TYPE>(max_blocks);

                keccak_table(context_type &context_object,
                             TYPE rlc_challenge,
                             std::size_t max_blocks_,
                             const keccak_table_input_type<FieldType> &private_input,
                             bool make_links = true) :
                    max_blocks(max_blocks_),
                    generic_component<FieldType,stage>(context_object) {

                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        TYPE theta = rlc_challenge;

                        std::size_t input_idx = 0;
                        std::size_t block_counter = 0;
                        std::vector<std::uint8_t> msg;
                        std::pair<TYPE, TYPE> hash;

                        while( block_counter < max_blocks ) {
                            if( input_idx < private_input.input.size() ){
                                msg = std::get<0>(private_input.input[input_idx]);
                                hash = std::get<1>(private_input.input[input_idx]);
                                input_idx++;
                            } else {
                                msg = {};
                                hash = keccak_component_hash<FieldType>(msg);
                            }
                            TYPE RLC_value = calculateRLC<FieldType>(msg, theta);
                            for( std::size_t block = 0; block < std::ceil(float(msg.size() + 1)/136); block++){
                                if( block != std::ceil(float(msg.size() + 1)/136) - 1){
                                    is_last[block_counter] = 0;
                                } else {
                                    is_last[block_counter] = 1;
                                }
                                RLC[block_counter] = RLC_value;
                                hash_hi[block_counter] = hash.first;
                                hash_lo[block_counter] = hash.second;
                                block_counter++;
                            }
                        }
                    }
                    // allocate everything. NB: this replaces the map from the original component
                    for(std::size_t i = 0; i < max_blocks; i++) {
                        allocate(is_last[i],0,i);
                        allocate(RLC[i],1,i);
                        allocate(hash_hi[i],2,i);
                        allocate(hash_lo[i],3,i);
                    }
                    // declare dynamic lookup table
                    lookup_table("keccak_table",std::vector<std::size_t>({0,1,2,3}),0,max_blocks);
                };
            };
        } // namespace bbf
    } // namespace blueprint
} // namespace nil
#endif
