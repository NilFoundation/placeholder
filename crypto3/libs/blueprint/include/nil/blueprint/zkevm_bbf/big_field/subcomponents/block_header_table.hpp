//---------------------------------------------------------------------------//
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
#include <functional>

#include <nil/blueprint/component.hpp>
#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/zkevm_bbf/types/zkevm_block.hpp>


namespace nil::blueprint::bbf::zkevm_big_field{
    // Component for block header table
    std::string field_name_from_tag(std::size_t index){
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
                return "logs_bloom";
            case 8:
                return "logs_bloom";
            case 9:
                return "logs_bloom";
            case 10:
                return "logs_bloom";
            case 11:
                return "logs_bloom";
            case 12:
                return "logs_bloom";
            case 13:
                return "logs_bloom";
            case 14:
                return "difficulty";
            case 15:
                return "number";
            case 16:
                return "gas_limit";
            case 17:
                return "gas_used";
            case 18:
                return "timestamp";
            case 19:
                return "extra_data";
            case 20:
                return "mix_hash";
            case 21:
                return "nonce";
            case 22:
                return "base_fee";
            case 23:
                return "withdrawals_root";
            case 24:
                return "blob_gas_used";
            case 25:
                return "excess_blob_gas";
            case 26:
                return "parent_beacon_root";
            case 27:
                return "requests_hash";
            case 28:
                return "block_hash";
            default:
                return "None";
        }
    }

    template<typename FieldType, GenerationStage stage>
    class block_header_table : public generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;

    public:
        using typename generic_component<FieldType,stage>::TYPE;

        using input_type = std::conditional_t<
            stage == GenerationStage::ASSIGNMENT, std::vector<zkevm_block>, std::monostate
        >;

        std::size_t max_blocks;

        std::vector<TYPE> block_number;
        std::vector<TYPE> tag;
        std::vector<std::vector<TYPE>> value;

        static std::size_t get_witness_amount(){
            return 35;
        }

        block_header_table(context_type &context_object, input_type input, std::size_t max_blocks_) : 
            max_blocks(max_blocks_),
            generic_component<FieldType,stage>(context_object) {

            std::size_t max_rows = 29 * max_blocks + 1;

            std::vector<TYPE> block_number = std::vector<TYPE>(max_rows);
            std::vector<TYPE> tag = std::vector<TYPE>(max_rows);
            std::vector<TYPE> selector = std::vector<TYPE>(max_rows);
            std::vector<std::vector<TYPE>> value = std::vector<std::vector<TYPE>>(max_rows, std::vector<TYPE>(32));
            
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                BOOST_ASSERT(input.size() <= max_blocks);

                std::size_t block_counter = 0;
                zkevm_block block;
                std::size_t cur_row = 0;
                while (block_counter < input.size()){
                    block = input[block_counter];
                    
                    TYPE bn = 0;
                    for (std::size_t i = 0; i < block.block_number.size(); i++){
                        bn += block.block_number[i] * (1 << (8*i));
                    }

                    for (std::size_t i = 0; i < 29; i++){
                        block_number[cur_row + i] = bn;
                        selector[cur_row + i] = 1;
                    }
                    if (block.fork_type <= 3 ) {
                        selector[cur_row + 27] = 0;
                    }
                    else if (block.fork_type <=2 ) {
                        selector[cur_row + 24] = 0;
                        selector[cur_row + 25] = 0;
                        selector[cur_row + 26] = 0;
                    }
                    else if (block.fork_type <= 1 ) {
                        selector[cur_row + 23] = 0;
                    }
                    else{
                        selector[cur_row + 22] = 0;
                    }

                    auto block_hash       = w_to_8(block.hash);
                    auto parent_hash      = w_to_8(block.parent_hash);
                    auto sha3_uncles      = w_to_8(block.sha3_uncles);
                    auto state_root       = w_to_8(block.state_root);
                    auto tx_root          = w_to_8(block.tx_root);
                    auto receipts_root    = w_to_8(block.receipts_root);
                    auto mix_hash         = w_to_8(block.mix_hash);
                    auto withdrawals_root = w_to_8(block.withdrawals_root);
                    auto pb_root          = w_to_8(block.parent_beacon_root);
                    auto requests_hash    = w_to_8(block.requests_hash);
                    auto coinbase         = w_to_8(block.miner);
                    for (std::size_t i = 0; i < 32; i++){
                        value[cur_row + 0][i]  = parent_hash[i];
                        value[cur_row + 1][i]  = sha3_uncles[i];
                        value[cur_row + 2][i]  = coinbase[i];
                        value[cur_row + 3][i]  = state_root[i];
                        value[cur_row + 4][i]  = tx_root[i];
                        value[cur_row + 5][i]  = receipts_root[i];
                        value[cur_row + 20][i] = mix_hash[i];
                        value[cur_row + 23][i] = withdrawals_root[i];
                        value[cur_row + 26][i] = pb_root[i];
                        value[cur_row + 27][i] = requests_hash[i];
                        value[cur_row + 28][i] = block_hash[i];
                    }
                    
                    for (std::size_t i = 0; i < 8; i++){
                        auto bloom_chunks = w_to_8(block.logs_bloom[i]);
                        for (std::size_t j = 0; j < 32; j++){
                            value[cur_row + 6 + i][j] = bloom_chunks[j];
                        }
                    }

                    for (std::size_t i = 1; i <= block.difficulty.size(); i++){
                        value[cur_row + 14][32 - i] = block.difficulty[block.difficulty.size() - i];
                    }

                    for (std::size_t i = 1; i <= block.block_number.size(); i++){
                    value[cur_row + 15][32 - i] = block.block_number[block.block_number.size() - i];
                    }
                    
                    for (std::size_t i = 1; i <= block.gas_limit.size(); i++){
                        value[cur_row + 16][32 - i] = block.gas_limit[block.gas_limit.size() - i];
                    }

                    for (std::size_t i = 1; i <= block.gas_used.size(); i++){
                        value[cur_row + 17][32 - i] = block.gas_used[block.gas_used.size() - i];
                    }
                    
                    for (std::size_t i = 1; i <= block.timestamp.size(); i++){
                        value[cur_row + 18][32 - i] = block.timestamp[block.timestamp.size() - i];
                    }

                    for (std::size_t i = 1; i <= block.extra_data.size(); i++){
                        value[cur_row + 19][32 - i] = block.extra_data[block.extra_data.size() - i];
                    }

                    for (std::size_t i = 1; i <= 8; i++){
                        value[cur_row + 21][32 - i] = block.nonce[8 - i];
                    }

                    BOOST_ASSERT(block.base_fee.size() <= 32);
                    for (std::size_t i = 1; i <= block.base_fee.size(); i++){
                        value[cur_row + 22][32 - i] = block.base_fee[block.base_fee.size() - i];
                    }

                    BOOST_ASSERT(block.blob_gas_used.size() <= 8);
                    BOOST_ASSERT(block.excess_blob_gas.size() <= 8);
                    for (std::size_t i = 1; i <= block.blob_gas_used.size(); i++){
                        value[cur_row + 24][32 - i] = block.blob_gas_used[block.blob_gas_used.size() - i];
                    }
                    for (std::size_t i = 1; i <= block.excess_blob_gas.size(); i++){
                        value[cur_row + 25][32 - i] = block.excess_blob_gas[block.excess_blob_gas.size() - i];
                    }
                    
                    TYPE field_tag = 1;
                    for (std::size_t i = 0; i < max_rows; i++){
                        tag[cur_row + i] = field_tag;
                        field_tag++;
                    }

                    block_counter++;
                    cur_row += 29;
                }
                while ( cur_row < max_rows ) {
                    selector[cur_row] = 0;
                    tag[cur_row] = 0;
                    block_number[cur_row] = 0;
                    for(std::size_t j = 0; j < 32; j++) value[cur_row][j] = 0;
                    cur_row++;
                }

                std::cout << std::left << std::setfill(' ') << std::setw(15) << "block number";
                std::cout << std::left << "|" << std::setfill(' ') << std::setw(20) << "field";
                std::cout << std::left << "|" << std::setfill(' ') << std::setw(10) << "selector";
                std::cout << std::left << "|" << std::setfill(' ') << std::setw(10) << "tag";
                std::cout << std::left << "|" << std::setfill(' ') << std::setw(64) << "value" << std::endl;
                std::cout << std::setfill('=') << std::setw(100) << "" << std::endl;

                for(std::size_t i = 0; i < max_rows; i++){
                    std::cout << std::left << std::setfill(' ') << std::setw(15) << block_number[i];
                    std::cout << std::left << std::setfill(' ') << std::setw(20) << field_name_from_tag( i % 30);
                    std::cout << std::left << std::setfill(' ') << std::setw(10) << selector[i];
                    std::cout << "|" << std::left <<  std::setfill(' ') << std::setw(10) << tag[i];
                    std::cout << "| 0x";
                    for(std::size_t k = 0; k < 32; k++){
                        std::cout << std::hex << std::right <<  std::setfill('0') << std::setw(2) << value[i][k];
                    }
                    std::cout << std::dec << std::endl;
                }

            }

            // allocate everything.
            for(std::size_t i = 0; i < max_rows; i++) {
                allocate(selector[i], 0, i);
                allocate(block_number[i], 1, i);
                allocate(tag[i], 2, i);
                for(std::size_t j = 0; j < 32; j++) allocate(value[i][j], 3+j, i);
            }

            // if constexpr (stage == GenerationStage::CONSTRAINTS) {
            //     std::size_t row = 1; 
            //     while (row < max_rows) {
            //         constrain(tag[row] - 1, "first tag is 1");
            //         for (std::size_t i = 1; i < 29; i++){
            //             constrain(tag[row + 1] - tag[row] - 1, "tag++");
            //             constrain(selector[row]*(selector[row]-1), "dynamic selector");
            //             constrain(block_number[row+1] - block_number[row]);
            //             row++;
            //         }
            //         row++;
            //     }
            //     // constrain(selector[row]);
            //     // constrain(tag[row]);
            //     // constrain(block_number[row]);
            //     // for (std::size_t j = 0; j < 32; j++) {
            //     //     constrain(value[row][j]);
            //     // }
            // }

            
            // declare dynamic lookup table
            std::vector<std::size_t> lookup_area;
            for (std::size_t i = 0; i < 35; i++) lookup_area.push_back(i);
            lookup_table("block_header_table", lookup_area, 0, max_rows);
        };
    };
}