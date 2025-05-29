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
// copies or substantial portions of the Sof,tware.
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

#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/bbf/components/rlp/rlp_field.hpp>
#include <nil/blueprint/bbf/components/rlp/util.hpp>
#include <nil/blueprint/bbf/components/hashes/keccak/util.hpp>

namespace nil::blueprint::bbf {

    template<typename FieldType, GenerationStage stage>
    class rlp_array : public generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;

        public:
            using typename generic_component<FieldType,stage>::TYPE;
            using typename generic_component<FieldType,stage>::table_params;
            using integral_type = typename FieldType::integral_type;
            using value_type = typename FieldType::value_type;
            // using RLP_FIELD = typename rlp_field<FieldType, stage>;

            struct input_type {
                std::conditional_t<
                    stage == GenerationStage::ASSIGNMENT,
                    std::vector<std::uint8_t>,
                    std::monostate
                > input;

                TYPE rlc_challenge;
            };


        static table_params get_minimal_requirements(std::vector<std::size_t> max_bytes, std::vector<bool> is_variable_len) {
            constexpr std::size_t witness = 12;
            constexpr std::size_t public_inputs = 1;
            constexpr std::size_t constants = 1;
            std::size_t rows = std::accumulate(max_bytes.begin(), max_bytes.end(), 0) + 9;
            return {witness, public_inputs, constants, rows};
        }

        static std::size_t get_witness_amount(){
            return 12;
        }

        static void allocate_public_inputs(
                context_type &context_object, input_type &input, std::vector<std::size_t> max_bytes, std::vector<bool> is_variable_len) {
            context_object.allocate(input.rlc_challenge, 0, 0, column_type::public_input);
        }

        TYPE rlc;
        std::vector<TYPE> all_bytes;
        std::vector<TYPE> all_is_prefix;
        std::vector<TYPE> all_is_len;
        std::vector<TYPE> all_is_last;

        rlp_array(context_type &context_object, input_type rlp_input, std::vector<std::size_t> max_bytes, std::vector<bool> is_variable_len, bool make_links = true) :
            generic_component<FieldType,stage>(context_object) {

            BOOST_ASSERT(is_variable_len.size() == max_bytes.size());

            std::size_t max_fields = max_bytes.size();
            std::size_t header_rows = 9;
            std::size_t total_max_bytes = header_rows;
            for(auto &t : max_bytes){
                total_max_bytes += t;
            }

            std::vector<TYPE> bytes = std::vector<TYPE>(header_rows);
            std::vector<TYPE> is_prefix = std::vector<TYPE>(header_rows);
            std::vector<TYPE> is_big = std::vector<TYPE>(header_rows);
            std::vector<TYPE> is_len = std::vector<TYPE>(header_rows);
            std::vector<TYPE> field_len = std::vector<TYPE>(header_rows);
            std::vector<TYPE> len_len = std::vector<TYPE>(header_rows);
            std::vector<TYPE> len_val = std::vector<TYPE>(header_rows);
            std::vector<TYPE> is_last = std::vector<TYPE>(header_rows);
            std::vector<TYPE> RLC = std::vector<TYPE>(total_max_bytes);
            std::vector<TYPE> rlc_challenge = std::vector<TYPE>(total_max_bytes);
            std::vector<TYPE> array_len = std::vector<TYPE>(total_max_bytes);
            std::vector<TYPE> array_is_last = std::vector<TYPE>(total_max_bytes);
            std::vector<TYPE> FIELD_LENGTHS = std::vector<TYPE>(max_fields);

            std::size_t offset = header_rows;
            for(std::size_t i = 0; i < max_fields; i++ ){
                assert(offset < total_max_bytes);
                FIELD_LENGTHS[i] = value_type(max_bytes[i]);
                allocate(FIELD_LENGTHS[i], 0, offset, column_type::constant);
                offset += max_bytes[i];
            }

            std::vector<std::size_t> rlp_field_area = {0,1,2,3,4,5,6,7,8}; 

            if constexpr (stage == GenerationStage::ASSIGNMENT) {  
                // BOOST_ASSERT(rlp_input.input.size() <= total_max_bytes );

                TYPE theta = rlp_input.rlc_challenge;
                for(std::size_t i = 0; i < total_max_bytes; i++){
                    rlc_challenge[i] = theta;
                }

                integral_type real_array_len = 0;
                integral_type real_len_len = 0;
                std::size_t cur = 1;
                bytes[0] = rlp_input.input[0];
                
                if(bytes[0] >= 0xc0 && bytes[0] <= 0xf7){
                    is_prefix[0] = 1;
                    array_len[0] = bytes[0] - 0xc0;
                    real_array_len = integral_type(array_len[0].data);
                    RLC[0] = bytes[0] + theta * (array_len[0] + 1);
                    for(std::size_t i = 1; i < header_rows; i++){
                        RLC[i] = RLC[i-1];
                    }
                }
                if(bytes[0] >= 0xf8){
                    is_prefix[0] = 1;
                    is_big[0] = 1;
                    len_len[0] = bytes[0] - 0xf7;
                    real_len_len = integral_type(len_len[0].data);

                    auto rll = static_cast<std::size_t>(real_len_len);
                    for(std::size_t i = 1; i<=rll; i++){
                        bytes[i] = rlp_input.input[i];
                        is_len[i] = 1;
                        if(i == 1){
                            len_val[i] = bytes[i];
                        }else{
                            len_val[i] = bytes[i] + 256 * len_val[i-1];
                        }
                        len_len[i] = TYPE(real_len_len - i + 1);
                    }
                    len_val[0] = len_val[rll];
                    for(std::size_t i = rll+1; i < header_rows; i++){
                        len_val[i] = len_val[rll];
                    }
                    array_len[0] = len_val[0];

                    RLC[0] = bytes[0] + theta * (len_len[0] + array_len[0] + 1);
                    for(std::size_t i = 1; i <= rll; i++) {
                        RLC[i] = bytes[i] + theta * RLC[i-1]; 
                    }

                    for(std::size_t i = rll+1; i < header_rows; i++){
                        RLC[i] = RLC[i-1];
                    }
                }

                for(std::size_t i = 1; i< header_rows; i++){
                    array_len[i] =  array_len[0];
                }
                

                // std::cout << "bytes\tis_prefix\tis_big\tis_len\tarray_len\tlen_len\tlen_val\tis_last\ttheta\tRLC\n";
                // for(std::size_t row_index = 0; row_index < header_rows; row_index++){
                //         std::cout << std::hex << std::setfill('0') << std::setw(2) << bytes[row_index] << std::dec << " " << 
                //         is_prefix[row_index] << " " << 
                //         is_big[row_index] << " " << 
                //         is_len[row_index] << " " << 
                //         array_len[row_index] << " " << 
                //         len_len[row_index] << " " << 
                //         len_val[row_index] << " " << 
                //         is_last[row_index] << " " << 
                //         rlc_challenge[row_index] << " " << 
                //         RLC[row_index] << " " << std::endl;
                // }


                std::size_t field_index = 0;
                std::size_t cur_index = cur + static_cast<std::size_t>(real_len_len);
                std::size_t cur_row = header_rows;

                while(field_index < max_fields){
                    BOOST_ASSERT(cur_index < rlp_input.input.size());
                    std::vector<std::uint8_t> field_rlp = extract_next_field(rlp_input.input, cur_index, max_bytes[field_index]);
                    context_type ct = context_object.fresh_subcontext(rlp_field_area, cur_row, max_bytes[field_index]);
                    rlp_field<FieldType, stage> rlp_field_block(ct, field_rlp, max_bytes[field_index], is_variable_len[field_index], make_links);

                    array_len[cur_row] = array_len[cur_row-1] - 
                            (rlp_field_block.field_length + rlp_field_block.length_length + rlp_field_block.has_prefix);
                    
                    for(std::size_t i = cur_row + 1; i < cur_row + max_bytes[field_index]; i++){
                        array_len[i] = array_len[i-1];
                    }

                    for(std::size_t i = cur_row; i < cur_row + field_rlp.size(); i++){
                        RLC[i] = rlp_field_block.bytes[i - cur_row] + theta*RLC[i-1];
                    }
                    for(std::size_t i = cur_row + field_rlp.size(); i < cur_row + max_bytes[field_index]; i++){
                        RLC[i] = RLC[i-1];
                    }

                    cur_row += max_bytes[field_index];
                    cur_index += field_rlp.size();
                    field_index++;
                }

                auto real_rlc = calculateRLC<FieldType>(rlp_input.input, theta);
                // std::cout << "RLC: " << RLC[total_max_bytes - 1] << std::endl;
                // std::cout << "calculated RLC: " << real_rlc << std::endl;
                BOOST_ASSERT(RLC[total_max_bytes - 1] == real_rlc);
            }


            for(std::size_t i = 0; i < header_rows; i++){
                allocate(bytes[i], 0, i);
                allocate(is_prefix[i], 1, i);
                allocate(is_big[i], 2, i);
                allocate(is_len[i], 3, i);
                allocate(field_len[i], 4, i);
                allocate(len_len[i], 5, i);
                allocate(len_val[i], 6, i);
                allocate(is_last[i], 7, i);


                all_bytes.push_back(bytes[i]);
                all_is_len.push_back(is_len[i]);
                all_is_last.push_back(is_last[i]);
                all_is_prefix.push_back(is_prefix[i]);
            }

            for(std::size_t i = 0; i < total_max_bytes; i++){
                allocate(array_len[i], 8, i);
                allocate(array_is_last[i], 9, i);
                allocate(rlc_challenge[i], 10, i);
                allocate(RLC[i], 11, i);
            }

            if (make_links) {
                for(std::size_t i = 0; i < total_max_bytes; i++) {
                    copy_constrain(rlc_challenge[i], rlp_input.rlc_challenge);
                }
            }

            if constexpr (stage == GenerationStage::CONSTRAINTS) { 

                for(std::size_t i = 0; i < header_rows; i++) {
                    constrain(is_prefix[i]*(1-is_prefix[i]), "is_prefix is binary");
                    constrain(is_big[i]*(1-is_big[i]), "is_big is binary");
                    constrain(is_len[i]*(1-is_len[i]), "is_len is binary");
                    constrain(is_last[i]*(1-is_last[i]), "is_last is binary");
                    constrain(is_big[i]*(1-is_prefix[i]), "is_big only first row");
                    constrain((1-is_big[i])*is_prefix[i]*(bytes[i] - array_len[i] - 0xc0), "is_big false condition");
                    constrain(is_big[i]*(len_val[i] - array_len[i]), "len_val is equal to array_len for big inputs");
                    constrain(is_big[i]*(bytes[i] - len_len[i] - 0xf7), "is_big true condition");
                    if(i < header_rows - 1) {
                        constrain(is_len[i]*(len_len[i] - len_len[i+1] - 1));
                        
                    }
                    if(i >= 1) {
                        constrain(is_len[i-1]*is_len[i]*(len_val[i-1] * 256 + bytes[i] - len_val[i]));
                        constrain((1-is_len[i])*(len_val[i] - len_val[i-1]));
                        constrain((1-is_len[i])*(RLC[i] - RLC[i-1]), "RLC stays same for non-header bytes after prefix");
                        constrain(is_len[i]*(RLC[i] - bytes[i] - rlc_challenge[i]*RLC[i-1]), "otherwise update RLC");
                    }
                }
                copy_constrain(len_val[1], bytes[1]);
                copy_constrain(len_val[0],len_val[header_rows - 1]);
                constrain((1-is_big[0])*(RLC[0] - bytes[0] - rlc_challenge[0]*(array_len[0]+1)), "rlc computation start value if not big");
                constrain(is_big[0]*(RLC[0] - bytes[0] - rlc_challenge[0]*(array_len[0]+1 + len_len[0])), "rlc computation start value if big");


                std::size_t field_index = 0;
                std::size_t cur_row = header_rows;
                while(field_index < max_fields){
                    context_type ct = context_object.fresh_subcontext(rlp_field_area, cur_row, max_bytes[field_index]);
                    rlp_field<FieldType, stage> rlp_field_block(ct, rlp_input.input, max_bytes[field_index], is_variable_len[field_index], make_links);

                    all_bytes.insert(all_bytes.end(), rlp_field_block.bytes.begin(), rlp_field_block.bytes.end());
                    all_is_prefix.insert(all_is_prefix.end(), rlp_field_block.is_prefix.begin(), rlp_field_block.is_prefix.end());
                    all_is_len.insert(all_is_len.end(), rlp_field_block.is_len.begin(), rlp_field_block.is_len.end());
                    all_is_last.insert(all_is_last.end(), rlp_field_block.is_last.begin(), rlp_field_block.is_last.end());

                    constrain(array_len[cur_row - 1] - array_len[cur_row] -  (rlp_field_block.field_length + rlp_field_block.length_length + rlp_field_block.has_prefix));
                    if(is_variable_len[field_index] == false) {
                        constrain((rlp_field_block.field_length + rlp_field_block.length_length + rlp_field_block.has_prefix) - FIELD_LENGTHS[field_index], "fixed length field");
                    }
                    for(std::size_t i = cur_row + 1; i < cur_row + max_bytes[field_index]; i++) {
                        copy_constrain(array_len[i], array_len[i-1]);
                    }
                    for(std::size_t i = cur_row; i < cur_row + max_bytes[field_index]; i++){
                        constrain((rlp_field_block.is_last[i - cur_row] - 1)*rlp_field_block.is_last[i - cur_row]*(RLC[i] - RLC[i - 1]), "rlc no update for padding rows");
                        constrain((rlp_field_block.is_last[i - cur_row] - 2)*(RLC[i] - rlp_field_block.bytes[i - cur_row] - rlc_challenge[i] * RLC[i - 1]), "otherwise rlc update");
                    }

                    cur_row += max_bytes[field_index];
                    field_index++;
                }
                constrain(array_len[total_max_bytes - 1], "last array len is zero");
            }

            rlc = RLC[total_max_bytes - 1];
        }
    };
} // namespace nil::blueprint::bbf
