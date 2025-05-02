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
// @file Declaration of interfaces for PLONK BBF is_zero component class
//---------------------------------------------------------------------------//

#pragma once

#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/bbf/components/rlp/rlp_field.hpp>

namespace nil::blueprint::bbf {

    std::vector<std::uint8_t> extract_next_field(std::vector<std::uint8_t> &buffer, std::size_t start, std::size_t max_bytes){
        std::vector<std::uint8_t> result;
        std::uint8_t first_byte = buffer[start];
        if(first_byte < 0x80){
            result.push_back(first_byte);
        } 
        if(first_byte >= 0x80 && first_byte <= 0xb7){
            std::size_t len = (uint8_t) (first_byte - 0x80);
            std::size_t end = start + len + 1;
            end = std::min(end, buffer.size());
            result.insert(result.begin(), buffer.begin() + start, buffer.begin() + end);
        }
        if(first_byte >= 0xb8 && first_byte <= 0xbf){
            std::size_t byte_len_len = (uint8_t) (first_byte - 0xb7);
            std::size_t len = 0;
            for(std::size_t i = 0; i < byte_len_len; i++){
                len = (len << 8) + buffer[start + i + 1];
            }
            
            std::size_t end = start + byte_len_len + len + 1;
            end = std::min(end, buffer.size());
            result.insert(result.begin(), buffer.begin() + start, buffer.begin() + end);
        }
        BOOST_ASSERT(result.size() <= max_bytes);
        return result;
    }

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

            using input_type = typename rlp_field<FieldType, stage>::input_type;


        static table_params get_minimal_requirements(std::vector<std::size_t> max_bytes) {
            constexpr std::size_t witness = 11;
            constexpr std::size_t public_inputs = 1;
            constexpr std::size_t constants = 0;
            std::size_t rows = 9;
            for(auto &t : max_bytes){
                rows+= t;
            }
            return {witness, public_inputs, constants, rows};
        }

        static void allocate_public_inputs(
                context_type &context_object, input_type &input, std::vector<std::size_t> max_bytes) {
            context_object.allocate(input.rlc_challenge, 0, 0, column_type::public_input);
        }

        rlp_array(context_type &context_object, input_type rlp_input, std::vector<std::size_t> max_bytes, bool make_links = true) :
            generic_component<FieldType,stage>(context_object) {

            std::size_t max_fields = max_bytes.size();
            std::size_t header_rows = 9;
            std::size_t total_max_bytes = header_rows;
            for(auto &t : max_bytes){
                total_max_bytes += t;
            }

            std::cout << "total max bytes: " << total_max_bytes << std::endl;

            std::vector<TYPE> bytes = std::vector<TYPE>(total_max_bytes);
            std::vector<TYPE> is_prefix = std::vector<TYPE>(total_max_bytes);
            std::vector<TYPE> is_big = std::vector<TYPE>(total_max_bytes);
            std::vector<TYPE> is_len = std::vector<TYPE>(total_max_bytes);
            std::vector<TYPE> field_len = std::vector<TYPE>(total_max_bytes);
            std::vector<TYPE> len_len = std::vector<TYPE>(total_max_bytes);
            std::vector<TYPE> len_val = std::vector<TYPE>(total_max_bytes);
            std::vector<TYPE> is_last = std::vector<TYPE>(total_max_bytes);
            std::vector<TYPE> rlc = std::vector<TYPE>(total_max_bytes);
            std::vector<TYPE> array_len = std::vector<TYPE>(total_max_bytes);
            std::vector<TYPE> array_is_last = std::vector<TYPE>(total_max_bytes);

            std::vector<std::size_t> rlp_field_area = {0,1,2,3,4,5,6,7,8,9}; 

            if constexpr (stage == GenerationStage::ASSIGNMENT) {  
                // BOOST_ASSERT(rlp_input.input.size() <= total_max_bytes );

                integral_type real_array_len = 0;
                integral_type real_len_len = 0;
                std::size_t cur = 1;
                bytes[0] = rlp_input.input[0];
                
                if(bytes[0] >= 0xc0 && bytes[0] <= 0xf7){
                    is_prefix[0] = 1;
                    array_len[0] = bytes[0] - 0xc0;
                    real_array_len = integral_type(array_len[0].data);
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
                    for(std::size_t i = 1; i<=rll; i++){
                        array_len[i] =  len_val[0];
                    }
                }

                std::cout << "bytes\tis_prefix\tis_big\tis_len\tfield_len\tlen_len\tlen_val\tis_last\n";
                for(std::size_t row_index = 0; row_index < header_rows; row_index++){
                        std::cout << std::hex << std::setfill('0') << std::setw(2) << bytes[row_index] << std::dec << " " << 
                        is_prefix[row_index] << " " << 
                        is_big[row_index] << " " << 
                        is_len[row_index] << " " << 
                        field_len[row_index] << " " << 
                        len_len[row_index] << " " << 
                        len_val[row_index] << " " << 
                        is_last[row_index] << " " << 
                        rlc[row_index] << " " << std::endl;
                }

                std::size_t field_index = 0;
                std::size_t cur_index = cur + static_cast<std::size_t>(real_len_len);
                std::size_t cur_row = header_rows;
                while(field_index < max_fields){
                    BOOST_ASSERT(cur_index < rlp_input.input.size());
                    std::vector<std::uint8_t> field_rlp = extract_next_field(rlp_input.input, cur_index, max_bytes[field_index]);
                    context_type ct = context_object.fresh_subcontext(rlp_field_area, cur_row, max_bytes[field_index]);
                    rlp_field<FieldType, stage> rlp_field_block(ct, {field_rlp, rlp_input.rlc_challenge}, max_bytes[field_index], make_links);
                    cur_row += max_bytes[field_index];
                    cur_index += field_rlp.size();
                    field_index++;
                }
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
                allocate(rlc[i], 8, i);
                allocate(array_len[i], 9, i);
                allocate(array_is_last[i], 10, i);
            }

            if constexpr (stage == GenerationStage::CONSTRAINTS) { 

                for(std::size_t i = 0; i < header_rows; i++){
                    constrain(is_prefix[i]*(1-is_prefix[i]), "is_prefix is binary");
                    constrain(is_big[i]*(1-is_big[i]), "is_big is binary");
                    constrain(is_len[i]*(1-is_len[i]), "is_len is binary");
                    constrain(is_last[i]*(1-is_last[i]), "is_last is binary");
                    constrain(is_big[i]*(1-is_prefix[i]), "is_big only first row");
                    constrain((1-is_big[i])*is_prefix[i]*(bytes[i] - array_len[i] - 0xc0), "is_big false condition");
                    constrain(is_big[i]*(len_val[i] - array_len[i]), "len_val is equal to array_len for big inputs");
                    constrain(is_big[i]*(bytes[i] - len_len[i] - 0xf7), "is_big true condition");
                    if(i < header_rows - 1){
                        constrain(is_len[i]*(len_len[i] - len_len[i+1] - 1));
                        
                    }
                    if(i >= 1){
                        constrain(is_len[i-1]*is_len[i]*(len_val[i-1] * 256 + bytes[i] - len_val[i]));
                        constrain((1-is_len[i])*(len_val[i] - len_val[i-1]));
                    }
                }
                copy_constrain(len_val[1], bytes[1]);
                copy_constrain(len_val[0],len_val[header_rows - 1]);


                std::size_t field_index = 0;
                std::size_t cur_row = header_rows;
                while(field_index < max_fields){
                    context_type ct = context_object.fresh_subcontext(rlp_field_area, cur_row, max_bytes[field_index]);
                    rlp_field<FieldType, stage> rlp_field_block(ct, rlp_input, max_bytes[field_index], make_links);
                    cur_row += max_bytes[field_index];
                    field_index++;
                }

            }
        }
    };
} // namespace nil::blueprint::bbf
