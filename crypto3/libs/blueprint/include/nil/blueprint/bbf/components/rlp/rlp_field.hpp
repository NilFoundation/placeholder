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
// @file Declaration of interfaces for PLONK BBF is_zero component class
//---------------------------------------------------------------------------//

#pragma once

#include <nil/blueprint/bbf/generic.hpp>

namespace nil::blueprint::bbf {
    template<typename FieldType, GenerationStage stage>
    class rlp_field : public generic_component<FieldType, stage> {
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

            struct input_type {
                std::conditional_t<
                    stage == GenerationStage::ASSIGNMENT,
                    std::vector<std::uint8_t>,
                    std::monostate
                > input;

                TYPE rlc_challenge;
            };


            static table_params get_minimal_requirements(std::size_t max_bytes, bool is_variable_len) {
            constexpr std::size_t witness = 9;
            constexpr std::size_t public_inputs = 1;
            constexpr std::size_t constants = 1;
            std::size_t rows = max_bytes;
            return {witness, public_inputs, constants, rows};
        }

        static void allocate_public_inputs(
                context_type &context_object, input_type &input, std::size_t max_blocks, bool is_variable_len) {
            context_object.allocate(input.rlc_challenge, 0, 0,
                                    column_type::public_input);
        }

        TYPE field_length;
        TYPE length_length;
        TYPE has_prefix;

        rlp_field(context_type &context_object, input_type rlp_input, std::size_t max_bytes, bool is_variable_len, bool make_links = true) :
            generic_component<FieldType,stage>(context_object) {

            std::vector<TYPE> bytes = std::vector<TYPE>(max_bytes);
            std::vector<TYPE> is_prefix = std::vector<TYPE>(max_bytes);
            std::vector<TYPE> is_big = std::vector<TYPE>(max_bytes);
            std::vector<TYPE> is_len = std::vector<TYPE>(max_bytes);
            std::vector<TYPE> field_len = std::vector<TYPE>(max_bytes);
            std::vector<TYPE> len_len = std::vector<TYPE>(max_bytes);
            std::vector<TYPE> len_val = std::vector<TYPE>(max_bytes);
            std::vector<TYPE> is_last = std::vector<TYPE>(max_bytes);
            std::vector<TYPE> rlc = std::vector<TYPE>(max_bytes);

            value_type fixed_length = (value_type) max_bytes;

            if constexpr (stage == GenerationStage::ASSIGNMENT) {  
                BOOST_ASSERT(rlp_input.input.size() <= max_bytes);
                integral_type real_field_len = 0;
                integral_type real_len_len = 0;
                std::size_t cur = 1;
                std::size_t has_prefix = 1;
                bytes[0] = rlp_input.input[0];
                if(bytes[0] < 0x80) {
                    field_len[0] = TYPE(rlp_input.input.size());
                    has_prefix = 0;
                }
                if(bytes[0] >= 0x80 && bytes[0] <= 0xbf) {
                    is_prefix[0] = 1;
                }
                if(bytes[0] >= 0x80 && bytes[0] <= 0xb7){
                    field_len[0] =  bytes[0] - 0x80;
                }
                if(bytes[0] >= 0xb8 && bytes[0] <= 0xbf){
                    is_big[0] = 1;
                    len_len[0] = bytes[0] - 0xb7;
                    real_len_len = integral_type(len_len[0].data);

                    auto rll = static_cast<std::size_t>(real_len_len);
                    for(std::size_t i = rll; i>=1; i--){
                        bytes[i] = rlp_input.input[i];
                        is_len[i] = 1;
                        if(i == rll){
                            len_val[i] = bytes[i];
                        }else{
                            len_val[i] = bytes[i] * 256 + len_val[i+1];
                        }
                        len_len[i] = TYPE(real_len_len - i + 1);
                    }
                    len_val[0] = len_val[1];
                    
                    field_len[0] = len_val[0];
                    for(std::size_t i = static_cast<std::size_t>(real_len_len); i>0; i--){
                        field_len[i] =  len_val[0];
                    }
                }

                real_field_len = integral_type(field_len[0].data);
                cur += static_cast<std::size_t>(real_len_len);
                
                while(cur < rlp_input.input.size()){
                    bytes[cur] = rlp_input.input[cur];
                    field_len[cur] = TYPE(real_field_len - (cur - real_len_len - has_prefix));
                    cur++;
                }
                is_last[cur-1] = 1;

                BOOST_ASSERT(cur <= max_bytes);

                while(cur < max_bytes){
                    field_len[cur] = field_len[cur - 1] - 1;
                    cur++;
                }

                std::cout << "bytes\tis_prefix\tis_big\tis_len\tfield_len\tlen_len\tlen_val\tis_last\n";
                for(std::size_t row_index = 0; row_index< max_bytes; row_index++){
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
            }

            for(std::size_t i = 0; i < max_bytes; i++){
                allocate(bytes[i], 0, i);
                allocate(is_prefix[i], 1, i);
                allocate(is_big[i], 2, i);
                allocate(is_len[i], 3, i);
                allocate(field_len[i], 4, i);
                allocate(len_len[i], 5, i);
                allocate(len_val[i], 6, i);
                allocate(is_last[i], 7, i);
                allocate(rlc[i], 8, i);
            }

            if(!is_variable_len){
                constrain(field_len[0] + is_prefix[0] + len_len[0] - fixed_length);
            }
            constrain((1-is_prefix[0])*(field_len[0] - 1), "single byte up to 0x79 has no prefix");
            for(std::size_t i = 0; i < max_bytes; i++){
                // lookup(bytes[i], "byte_range_table/full");
                constrain(is_prefix[i]*(1-is_prefix[i]), "is_prefix is binary");
                constrain(is_big[i]*(1-is_big[i]), "is_big is binary");
                constrain(is_len[i]*(1-is_len[i]), "is_len is binary");
                constrain(is_last[i]*(1-is_last[i]), "is_last is binary");
                constrain(is_big[i]*(1-is_prefix[i]), "is_big only first row");
                constrain((1-is_big[i])*is_prefix[i]*(bytes[i] - field_len[i] - 0x80), "is_big false condition");
                constrain(is_big[i]*(bytes[i] - len_len[i] - 0xb7), "is_big true condition");
                constrain(is_big[i]*(len_val[i] - field_len[i]), "len_val is equal to field_len if is_big");
                constrain(is_prefix[i]*is_last[i]*field_len[i], "empty string has len zero");
                constrain((1-is_prefix[i])*is_last[i]*(field_len[i] - 1), "field_len is 1 if is_last except is_prefix");
                constrain((1-is_len[i])*(1-is_prefix[i])*len_len[i]);
                if(i < max_bytes - 1){
                    constrain(is_prefix[i]*(field_len[i] - field_len[i+1]), "field_len stays same for the prefix byte");
                    constrain(is_big[i]*(len_len[i] - len_len[i+1]), "len_len stays same for prefix byte if is_big");
                    constrain(is_len[i]*(field_len[i] - field_len[i+1]), "field_len stays same for length bytes");
                    constrain((1-is_prefix[i])*(1-is_len[i])*(field_len[i] - field_len[i+1] - 1), "field_len decrements by 1");
                    constrain(is_len[i]*(len_len[i] - len_len[i+1] - 1), "len_len decrements by 1");
                }
            }

            field_length = field_len[0];
            length_length = len_len[0];
            has_prefix = is_prefix[0];
        }
    };
} // namespace nil::blueprint::bbf
