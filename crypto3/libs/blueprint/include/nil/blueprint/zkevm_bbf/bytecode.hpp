//---------------------------------------------------------------------------//
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

#include <nil/blueprint/zkevm_bbf/types/hashed_buffers.hpp>
#include <nil/blueprint/zkevm_bbf/subcomponents/bytecode_table.hpp>
#include <nil/blueprint/zkevm_bbf/subcomponents/keccak_table.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            template<typename FieldType, GenerationStage stage>
            class bytecode : public generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;

            public:
                using typename generic_component<FieldType,stage>::TYPE;
                struct input_type{
                    TYPE rlc_challenge;
                    typename std::conditional<stage == GenerationStage::ASSIGNMENT, zkevm_keccak_buffers, std::nullptr_t>::type bytecodes;
                    typename std::conditional<stage == GenerationStage::ASSIGNMENT, zkevm_keccak_buffers, std::nullptr_t>::type keccak_buffers;
                };

                std::size_t max_bytecode_size;
                std::size_t max_keccak_blocks;

                static nil::crypto3::zk::snark::plonk_table_description<FieldType>  get_table_description(
                    std::size_t max_bytecode_size_,
                    std::size_t max_keccak_blocks_,
                    bool make_links = true
                ){
                    nil::crypto3::zk::snark::plonk_table_description<FieldType> desc(15, 1, 10, 10);
                    desc.usable_rows_amount = max_bytecode_size_ + max_keccak_blocks_;
                    return desc;
                }

                bytecode(context_type &context_object,
                    input_type input,
                    std::size_t max_bytecode_size_,
                    std::size_t max_keccak_blocks_,
                    bool make_links = true
                ) : max_bytecode_size(max_bytecode_size_),
                    max_keccak_blocks(max_keccak_blocks_),
                    generic_component<FieldType,stage>(context_object)
                {
                    using Bytecode_Table = bytecode_table<FieldType,stage>;
                    using Keccak_Table = keccak_table<FieldType,stage>;

                    std::vector<std::size_t> bytecode_lookup_area = {0,1,2,3,4,5};
                    std::vector<std::size_t> keccak_lookup_area = {0,1,2,3};
                    context_type bytecode_ct = context_object.subcontext(bytecode_lookup_area,0,max_bytecode_size);
                    context_type keccak_ct = context_object.subcontext( keccak_lookup_area, max_bytecode_size, max_bytecode_size + max_keccak_blocks);

                    Bytecode_Table bc_t = Bytecode_Table(bytecode_ct, input.bytecodes, max_bytecode_size);
                    Keccak_Table(keccak_ct, {input.rlc_challenge, input.keccak_buffers}, max_keccak_blocks);

                    const std::vector<TYPE> &tag = bc_t.tag;
                    const std::vector<TYPE> &index = bc_t.index;
                    const std::vector<TYPE> &value = bc_t.value;
                    const std::vector<TYPE> &is_opcode = bc_t.is_opcode;
                    const std::vector<TYPE> &hash_hi = bc_t.hash_hi;
                    const std::vector<TYPE> &hash_lo = bc_t.hash_lo;
                    std::vector<TYPE> rlc_challenge = std::vector<TYPE>(max_bytecode_size);
                    std::vector<TYPE> push_size = std::vector<TYPE>(max_bytecode_size);
                    std::vector<TYPE> length_left = std::vector<TYPE>(max_bytecode_size);
                    std::vector<TYPE> value_rlc = std::vector<TYPE>(max_bytecode_size);

                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        std::size_t cur = 0;
                        const auto &bytecodes = input.bytecodes.get_data();
                        for(std::size_t i = 0; i < bytecodes.size(); i++){
                            TYPE push_size_value = 0;
                            auto buffer = bytecodes[i].first;
                            TYPE length_left_value = buffer.size();
                            for(std::size_t j = 0; j < bytecodes[i].first.size(); j++, cur++){
                                auto byte = buffer[j];
                                rlc_challenge[cur] = input.rlc_challenge;
                                if( j == 0){ // HEADER
                                    push_size[cur] = 0;
                                    length_left[cur] = length_left_value;
                                    value_rlc[cur] = length_left_value;
                                    push_size_value = 0;
                                    length_left_value--;
                                    cur++;
                                }
                                // BYTE
                                rlc_challenge[cur] = input.rlc_challenge;
                                length_left[cur] = length_left_value;
                                if(push_size_value == 0){
                                    if(byte > 0x5f && byte < 0x80) push_size_value = byte - 0x5f;
                                } else {
                                    push_size_value--;
                                }
                                push_size[cur] = push_size_value;
                                value_rlc[cur] = value_rlc[cur - 1] * input.rlc_challenge + byte;
                                length_left_value--;
                            }
                        }
                    }
                    // allocate things that are not part of bytecode_table
                    for(std::size_t i = 0; i < max_bytecode_size; i++) {
                        allocate(push_size[i],6,i);
                        allocate(value_rlc[i],7,i);
                        allocate(length_left[i],8,i);
                        allocate(rlc_challenge[i],9,i);
                    }
                    // constrain all bytecode values
//                    if (make_links) {
//                        copy_constrain(input.rlc_challenge, rlc_challenge[0]);
//                    }
                    static const auto zerohash = zkevm_keccak_hash({});
                    for(std::size_t i = 0; i < max_bytecode_size; i++) {
                        constrain(tag[i] * (tag[i] - 1));    // 0. TAG is zeroes or ones -- maybe there will be third value for non-used rows
                        constrain((tag[i] - 1) * index[i]);     // 1. INDEX for HEADER and unused bytes is zero
                        constrain((tag[i] - 1) * (length_left[i] - value[i])); // 4. In contract header length_left == contract length
                        constrain(is_opcode[i] * (is_opcode[i] - 1)); // 7. is_opcode is zeroes or ones
                        constrain((tag[i] - 1) * is_opcode[i]); // 8. is_opcode on HEADER are zeroes
                        constrain((tag[i] - 1) * (value_rlc[i] - length_left[i])); // 14. value_rlc for HEADERS == 0;

                        if (i > 0) {
                            constrain((tag[i-1] - 1) * index[i]); // 2. INDEX for first contract byte is zero
                            constrain(tag[i-1] * tag[i] * (index[i] - index[i-1] - 1)); // 3. INDEX is incremented for all bytes
                            constrain(tag[i] * (length_left[i-1] - length_left[i] - 1)); // 5. In contract bytes each row decrement length_left
                            constrain(tag[i-1] * (tag[i] - 1) * length_left[i-1]); // 6. Length_left is zero for last byte in the contract
                            constrain((tag[i-1] - 1) * tag[i] * (is_opcode[i] - 1)); // 9. Fist is_opcode on BYTE after HEADER is 1
                            constrain(tag[i] * (is_opcode[i] - 1) * (push_size[i-1] - push_size[i] - 1)); // 10. PUSH_SIZE decreases for non-opcodes
                            constrain(is_opcode[i] * push_size[i-1]); // 11. before opcode push_size is always zero
                            constrain(tag[i] * (hash_hi[i-1] - hash_hi[i])); //12. for all bytes hash is similar to previous
                            constrain(tag[i] * (hash_lo[i-1] - hash_lo[i])); //13. for all bytes hash is similar to previous
                            constrain(tag[i] * (value_rlc[i] - value_rlc[i-1] * rlc_challenge[i] - value[i])); // 15. for all bytes RLC is correct
                            constrain(tag[i] * (rlc_challenge[i] - rlc_challenge[i-1])); //16. for each BYTEs rlc_challenge are similar
                        }
                        if (i> 0 && i < max_bytecode_size-1) {
                            constrain(tag[i+1] * (rlc_challenge[i] - rlc_challenge[i-1])); //17. rlc_challenge is similar for different contracts
                        }
                        lookup(tag[i]*value[i],"byte_range_table/full");
                        lookup(std::vector<TYPE>({value[i]*is_opcode[i], push_size[i]*is_opcode[i], is_opcode[i]}),"zkevm_opcodes/full");

                        if( i > 0 ){
                            lookup(std::vector<TYPE>({
                                tag[i] + 1 - tag[i], // TODO: update math::expression constructor with constant parameter
                                tag[i-1] * (1 - tag[i]) * value_rlc[i-1],
                                tag[i-1] * (1 - tag[i]) * hash_hi[i-1] + (1 - tag[i-1] * (1 - tag[i])) * w_hi<FieldType>(zerohash),
                                tag[i-1] * (1 - tag[i]) * hash_lo[i-1] + (1 - tag[i-1] * (1 - tag[i])) * w_lo<FieldType>(zerohash)
                            }), "keccak_table");
                        }
                    }
                };
            };
        }
    }
}
