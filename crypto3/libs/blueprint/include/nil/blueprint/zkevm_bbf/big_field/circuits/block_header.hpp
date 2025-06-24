// Copyright (c) 2025 Valeh Farzaliyev <estoniaa@nil.foundation>
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

#include <boost/multiprecision/cpp_int.hpp>
#include <functional>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/bbf/components/rlp/rlp_array.hpp>
#include <nil/blueprint/zkevm_bbf/util.hpp>
#include <nil/blueprint/bbf/components/hashes/keccak/util.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/subcomponents/keccak_table.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/subcomponents/block_header_table.hpp>

namespace nil::blueprint::bbf::zkevm_big_field{

    std::string field_name_from_index(std::size_t index){
        switch(index) {
            case 0:
                return "parent_hash";
            case 1:
                return "sha3_uncles";
            case 2:
                return "miner";
            case 3:
                return "state_root";
            case 4:
                return "transactions_root";
            case 5:
                return "receipts_root";
            case 6:
                return "logs_bloom";
            case 7:
                return "difficulty";
            case 8:
                return "number";
            case 9:
                return "gas_limit";
            case 10:
                return "gas_used";
            case 11:
                return "timestamp";
            case 12:
                return "extra_data";
            case 13:
                return "mix_hash";
            case 14:
                return "nonce";
            case 15:
                return "base_fee";
            case 16:
                return "withdrawals_root";
            case 17:
                return "blob_gas_used";
            case 18:
                return "excess_blob_gas";
            case 19:
                return "parent_beacon_root";
            case 20:
                return "requests_hash";
            case 21:
                return "block_hash";
            default:
                return "None";
        }
    }

    template<typename FieldType, GenerationStage stage>
    class block_header : public generic_component<FieldType, stage>{
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;

        using KeccakTable = keccak_table<FieldType, stage>;
        using BlockHeaderTable = block_header_table<FieldType, stage>;
        using RLPArray = rlp_array<FieldType, stage>;

    public:

        using typename generic_component<FieldType, stage>::table_params;
        using typename generic_component<FieldType, stage>::TYPE;
        
        using value_type = typename FieldType::value_type;
        using field_integral_type = typename FieldType::integral_type;
        using zkevm_word_type = nil::blueprint::zkevm_word_type;
        
        struct input_type {
            typename BlockHeaderTable::input_type input_blocks;
            TYPE rlc_challenge;
        };


        const std::vector<std::vector<std::size_t>> HEADER_FIELDS_MAX_BYTES = {
            {33,33,21,33,33,33,259,8,5,5,5,5,33,33,9},                     // pre-London (legacy)
            {33,33,21,33,33,33,259,8,5,5,5,5,33,33,9,33},                  // London
            {33,33,21,33,33,33,259,8,5,5,5,5,33,33,9,33,33},               // Shapella
            {33,33,21,33,33,33,259,8,5,5,5,5,33,33,9,33,33,9,9,33},        // Dencun
            {33,33,21,33,33,33,259,8,5,5,5,5,33,33,9,33,33,9,9,33,33}      // Pectra
        };

        const std::vector<std::vector<bool>> HEADER_FIELDS_IS_VARIABLE_LENGTH = {
            /* pre-London (legacy) */
            {false, false, false, false, false, false, false, true, true, true, true, true, true, false, false},                     
            /* LONDON */
            {false, false, false, false, false, false, false, true, true, true, true, true, true, false, false, true},                  
            /* Shapella */
            {false, false, false, false, false, false, false, true, true, true, true, true, true, false, false, true, false},
            /* Dencun */
            {false, false, false, false, false, false, false, true, true, true, true, true, true, false, false, true, false, true, true, false},
            /* Pectra */
            {false, false, false, false, false, false, false, true, true, true, true, true, true, false, false, true, false, true, true, false, false}
        };

        static table_params get_minimal_requirements(std::size_t fork_type) {
            std::array<std::size_t, 5> max_bytes = {548, 581, 614, 665, 698};
            return {
                .witnesses = 36 + RLPArray::get_witness_amount() + KeccakTable::get_witness_amount() + BlockHeaderTable::get_witness_amount(),
                .public_inputs = 1,
                .constants = 1,
                .rows = max_bytes[fork_type] + 10
            };
        }

        static void allocate_public_inputs(context_type &context_object, input_type &input, std::size_t fork_type) {
            context_object.allocate(input.rlc_challenge, 0, 0, column_type::public_input);
        }

        std::vector<TYPE> result = std::vector<TYPE>(32);

        block_header(context_type &context_object, const input_type& input, std::size_t fork_type, bool make_links = true) 
            : generic_component<FieldType, stage>(context_object){
            
            std::size_t max_bytes = std::accumulate(HEADER_FIELDS_MAX_BYTES[fork_type].begin(), HEADER_FIELDS_MAX_BYTES[fork_type].end(), 0);
            std::size_t max_rows = max_bytes + 10;
            std::size_t keccak_max_blocks = ((max_bytes + 135 ) / 136 );
            std::size_t max_blocks = 1;
            

            std::vector<TYPE> is_constructed = std::vector<TYPE>(max_rows);
            std::vector<TYPE> is_block_number= std::vector<TYPE>(max_rows);
            std::vector<TYPE> tag = std::vector<TYPE>(max_rows);
            std::vector<std::vector<TYPE>> value = std::vector<std::vector<TYPE>>(max_rows, std::vector<TYPE>(32));
            std::vector<TYPE> block_number = std::vector<TYPE>(max_rows);
            TYPE rlc;

            std::vector<std::size_t> rlp_area;
            for( std::size_t i = 0; i < RLPArray::get_witness_amount(); i++){
                rlp_area.push_back(i);
            }

            std::vector<std::size_t> keccak_lookup_area;
            for( std::size_t i = 0; i < KeccakTable::get_witness_amount(); i++){
                keccak_lookup_area.push_back(48+i);
            }

            std::vector<std::size_t> block_header_lookup_area;
            for( std::size_t i = 0; i < BlockHeaderTable::get_witness_amount(); i++){
                block_header_lookup_area.push_back(52+i);
            }

            typename KeccakTable::private_input_type keccak_buffers;
            typename BlockHeaderTable::input_type block_header_inputs;

            if constexpr (stage == GenerationStage::ASSIGNMENT){
                BOOST_ASSERT(input.input_blocks.size() <= max_blocks);

                std::size_t block_counter = 0;
                zkevm_block block;
                while (block_counter < max_blocks) {
                    if (block_counter < input.input_blocks.size()) {
                        block = input.input_blocks[block_counter];
                        
                        context_type rlp_ct = context_object.subcontext(rlp_area, 0, max_rows - 1);
                        auto encoded_rlp = block.rlp_encoding;
                        RLPArray rlp_array_block(rlp_ct, 
                            {encoded_rlp, input.rlc_challenge}, 
                            HEADER_FIELDS_MAX_BYTES[fork_type], 
                            HEADER_FIELDS_IS_VARIABLE_LENGTH[fork_type], 
                            make_links
                        );

                        // do the extraction here
                        TYPE field_tag = 1;
                        std::size_t row = 9;
                        std::size_t offset = 3;
                        TYPE bn;
                        std::cout << std::left << std::setfill(' ') << std::setw(20) << "field";
                        std::cout << std::left << "|" << std::setfill(' ') << std::setw(10) << "tag";
                        std::cout << std::left << "|" << std::setfill(' ') << std::setw(64) << "value" << std::endl;
                        std::cout << std::setfill('=') << std::setw(100) << "" << std::endl;
                        for (std::size_t field_index = 0; field_index < HEADER_FIELDS_MAX_BYTES[fork_type].size(); field_index++){
                            
                            std::size_t field_rlp_length = HEADER_FIELDS_MAX_BYTES[fork_type][field_index];
                            std::size_t field_length = extract_next_field_length(encoded_rlp, offset, field_rlp_length);
                            std::size_t diff = 0;

                            if(field_length <= 55) diff = 1;
                            else if(field_length > 55 && field_length < 256) { diff = 2; } // skip first length byte
                            else if(field_length >= 256 && field_length < 65536) { diff = 3; } // skip second length byte

                            for (std::size_t j = 0; j < diff; j++){
                                tag[row] = field_tag;
                                row++;
                                offset++;
                            }
                            
                            for(std::size_t j = 0; j < field_length; j++) {

                                value[row][0] = TYPE(encoded_rlp[offset]);
                                for(std::size_t k = 31; k > 0; k--) {
                                    if((j % 32) == 0) value[row][k] = 0;  // if-else redundant?
                                    else value[row][k] = value[row-1][k-1]; // left shift bytes in value cells
                                }

                                if( (j > 0) && ((j%32) == 0)) {
                                    is_constructed[row-1] = 1;
                                    field_tag++;

                                    std::cout << std::left << std::setfill(' ') << std::setw(20) << field_name_from_index(field_index);
                                    std::cout << "|" << std::left <<  std::setfill(' ') << std::setw(10) << field_tag - 1;
                                    std::cout << "| 0x";
                                    for(std::size_t k = 0; k < 32; k++){
                                        std::cout << std::hex << std::right << std::setfill('0') << std::setw(2) << value[row-1][31-k];
                                    }
                                    std::cout << std::dec << std::endl;
                                }

                                tag[row] = field_tag;
                                row++;
                                offset++;
                            }

                            is_constructed[row-1] = 1;

                            std::cout << std::left << std::setfill(' ') << std::setw(20) << field_name_from_index(field_index);
                            std::cout << "|" << std::left <<  std::setfill(' ') << std::setw(10) << field_tag;
                            std::cout << "| 0x";
                            for(std::size_t k = 0; k < 32; k++){
                                std::cout << std::hex << std::right <<  std::setfill('0') << std::setw(2) << value[row-1][31-k];
                            }
                            std::cout << std::dec << std::endl;
                            
                            if(field_index == 8) {
                                bn = value[row-1][3] + value[row-1][2] * 256 + value[row-1][1] * (65536)  + value[row-1][0] * (65536 * 256);
                                is_block_number[row-1] = 1;
                            }

                            for(std::size_t j = field_length; j < field_rlp_length - diff; j++) {
                                tag[row] = field_tag;
                                row++;
                            }
                            field_tag++;
                        }

                        for (std::size_t r = 0; r < max_rows; r++) {
                            block_number[r] = bn;
                        }

                        block_header_inputs.push_back(block);
                        keccak_buffers.new_buffer(encoded_rlp);
                        zkevm_word_type block_hash = zkevm_keccak_hash(encoded_rlp);
                        auto block_hash_to8 = w_to_8(block_hash);

                        // last row is for block_hash (selector 21)
                        rlc = calculateRLC<FieldType>(encoded_rlp, input.rlc_challenge);
                        is_constructed[max_rows - 1] = 1;
                        tag[max_rows - 1] = TYPE(29);
                        for(std::size_t i = 0; i < 32; i++) {
                            value[max_rows - 1][i] = block_hash_to8[31-i];
                        }

                        std::cout << std::left << std::setfill(' ') << std::setw(20) << field_name_from_index(21);
                        std::cout << "|" << std::left <<  std::setfill(' ') << std::setw(10) << tag[max_rows - 1];
                        std::cout << "| 0x";
                        for(std::size_t k = 0; k < 32; k++){
                            std::cout << std::hex << std::right <<  std::setfill('0') << std::setw(2) << value[max_rows-1][31-k];
                        }
                        std::cout << std::dec << std::endl;
                        std::cout << "block number: " << bn << std::endl;
                    }
                    else{
                        
                    }
                    block_counter++;
                }
            }

            allocate(rlc, 11, max_rows - 1);
            for(std::size_t row = 0; row < max_rows; row++){
                allocate(is_constructed[row], 12, row);
                allocate(is_block_number[row], 13, row);
                allocate(block_number[row], 14, row);
                allocate(tag[row], 15, row);
                for(std::size_t i = 0; i < 32; i++) {
                    allocate(value[row][i], 16 + i, row);
                }
            }

            context_type keccak_ct = context_object.subcontext(keccak_lookup_area, 0, keccak_max_blocks);
            KeccakTable kt(keccak_ct, {input.rlc_challenge, keccak_buffers}, keccak_max_blocks);

            context_type block_header_ct = context_object.subcontext(block_header_lookup_area, 0, max_rows);
            BlockHeaderTable bht(block_header_ct, input.input_blocks, max_blocks); 

            if constexpr (stage == GenerationStage::CONSTRAINTS) {
                for(std::size_t i = 0; i < max_blocks; i++) {
                    context_type ct = context_object.subcontext(rlp_area, 0, max_rows - 1);
                    RLPArray rlp_array_block(ct, 
                        {input.input_blocks, input.rlc_challenge}, 
                        HEADER_FIELDS_MAX_BYTES[fork_type], 
                        HEADER_FIELDS_IS_VARIABLE_LENGTH[fork_type], 
                        make_links
                    );

                    copy_constrain(rlc, rlp_array_block.rlc);
                }

                // 
                // for(std::size_t row = 0; row < max_rows - 1; row++) {
                //     constrain((1-rlp_array_block.all_is_prefix[row])*(1-rlp_array_block.all_is_len[row])*(value[row][0] - rlp_array_block.all_bytes[row]), "value[row][0] = byte[row]");
                //     constrain((rlp_array_block.all_is_prefix[row] + rlp_array_block.all_is_len[row])*(value[row][0]), "value[row][0] = 0");
                //     // constrain(rlp_array_block.all_is_last[row]*(2-rlp_array_block.all_is_last[row])*(is_constructed[row] - 1), "is_constructed = 1 when is_last = 1");
                //     // constrain((1-rlp_array_block.all_is_last[row])*is_constructed[row], "is_constructed = 0 otherwise");
                // }
                auto block_hash = chunks8_to_chunks128_reversed<TYPE>(value[max_rows - 1]);
                lookup({is_constructed[max_rows-1], rlc, block_hash.first, block_hash.second}, "keccak_table");

                for(std::size_t row = 0; row < 9; row++) constrain(tag[row], "tag is 0 for header rows");

                constrain(tag[9] - 1);
                // add other tag constraints
                constrain(tag[max_rows-1] - 29, "block hash tag is 29");

                for(std::size_t row = 0; row < max_rows; row++) {

                    constrain(is_constructed[row]*(is_constructed[row]-1), "is_constructed is 0 or 1");
                    constrain(is_block_number[row]*(is_block_number[row]-1));
                    constrain(is_constructed[row]*is_block_number[row]*
                        (block_number[row] - (value[row][3] + value[row][2] * 256 + value[row][1] * (65536)  + value[row][0] * (65536 * 256))), 
                        "block number composition from values");

                    if(row > 1 && row < max_rows - 1) {
                        for(std::size_t i = 1; i < 32; i++){
                            constrain(is_constructed[row-1]*value[row][i], "values are 0 when after field is constructed");
                            constrain((1-is_constructed[row-1])*(value[row][i] - value[row-1][i-1]), "values right shift");
                        }
                    }

                    if(row > 0) copy_constrain(block_number[row], block_number[row-1]);
                }

                for(std::size_t row = 10; row < max_rows; row++){
                    auto tmp = std::vector<TYPE>();
                    tmp.push_back(is_constructed[row]);
                    tmp.push_back(is_constructed[row]*block_number[row]);
                    tmp.push_back(is_constructed[row]*tag[row]);
                    for(std::size_t i = 0; i < 32; i++){
                        tmp.push_back(is_constructed[row]*value[row][31-i]);
                    }
                    lookup(tmp, "block_header_table");
                }
            }   
        }
    };
}