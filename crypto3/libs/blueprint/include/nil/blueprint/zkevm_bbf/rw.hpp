//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova <d.tabalin@nil.foundation>
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


#include <nil/blueprint/zkevm_bbf/subcomponents/rw_table.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            template<typename FieldType, GenerationStage stage>
            class rw : public generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;
            public:
                using typename generic_component<FieldType,stage>::TYPE;
                using rw_table_type = rw_table<FieldType, stage>;
                using input_type = typename rw_table_type::input_type;
                using value = typename FieldType::value_type;
                using integral_type = boost::multiprecision::number<boost::multiprecision::backends::cpp_int_modular_backend<257>>;
            public:
                static constexpr std::size_t op_bits_amount = 4;
                static constexpr std::size_t diff_index_bits_amount = 5;

                static constexpr std::size_t id_chunks_amount = 2;
                static constexpr std::size_t address_chunks_amount = 10;
                static constexpr std::size_t storage_key_chunks_amount = 16;
                static constexpr std::size_t rw_id_chunks_amount = 2;
                static constexpr std::size_t chunks_amount = 30;

                static nil::crypto3::zk::snark::plonk_table_description<FieldType> get_table_description(std::size_t max_rw_size, std::size_t max_mpt_size){
                    nil::crypto3::zk::snark::plonk_table_description<FieldType> desc(rw_table_type::get_witness_amount() + 50, 0, 2, 4);
                    desc.usable_rows_amount = max_rw_size + max_mpt_size;
                    return desc;
                }

                template<std::size_t n>
                TYPE bit_tag_selector(std::array<TYPE, n> bits, std::size_t k){
                    TYPE result;
                    integral_type mask = (1 << n);
                    for( std::size_t bit_ind = 0; bit_ind < n; bit_ind++ ){
                        mask >>= 1;
                        TYPE bit_selector = (mask & k == 0) ? 0 - (bits[bit_ind] - 1) : bits[bit_ind];
                        if( bit_ind == 0)
                            result = bit_selector;
                        else
                            result *= bit_selector;
                    }
                    return result;
                }

                rw(context_type &context_object, const input_type &input, std::size_t max_rw_size, std::size_t max_mpt_size) :generic_component<FieldType,stage>(context_object) {
                    std::vector<std::size_t> rw_table_area;
                    for( std::size_t i = 0; i < rw_table_type::get_witness_amount(); i++ ) rw_table_area.push_back(i);

                    context_type rw_table_ct = context_object.subcontext(rw_table_area,0,max_rw_size);
                    rw_table_type t(rw_table_ct, input, max_rw_size, false);

                    const std::vector<TYPE>  &op = t.op;
                    const std::vector<TYPE>  &id = t.id;
                    const std::vector<TYPE>  &address = t.address;
                    const std::vector<TYPE>  &storage_key_hi = t.storage_key_hi;
                    const std::vector<TYPE>  &storage_key_lo = t.storage_key_lo;
                    const std::vector<TYPE>  &field_type = t.field_type;
                    const std::vector<TYPE>  &rw_id = t.rw_id;
                    const std::vector<TYPE>  &is_write = t.is_write;
                    const std::vector<TYPE>  &value_hi = t.value_hi;
                    const std::vector<TYPE>  &value_lo = t.value_lo;

                    std::vector<std::array<TYPE,op_bits_amount>> op_bits(max_rw_size);
                    std::vector<std::array<TYPE,diff_index_bits_amount>> diff_index_bits(max_rw_size);
                    std::vector<TYPE> is_first(max_rw_size);
                    std::vector<std::array<TYPE,chunks_amount>> chunks(max_rw_size);
                    std::vector<TYPE> diff(max_rw_size);
                    std::vector<TYPE> inv_diff(max_rw_size);
                    std::vector<TYPE> value_before_hi(max_rw_size);
                    std::vector<TYPE> value_before_lo(max_rw_size);
                    std::vector<TYPE> state_root_hi(max_rw_size);
                    std::vector<TYPE> state_root_lo(max_rw_size);
                    std::vector<TYPE> state_root_before_hi(max_rw_size);
                    std::vector<TYPE> state_root_before_lo(max_rw_size);
                    std::vector<TYPE> is_last(max_rw_size);
                    std::vector<TYPE> sorted;
                    std::vector<TYPE> sorted_prev;

                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        auto rw_trace = input.get_rw_ops();
                        for( std::size_t i = 0; i < rw_trace.size(); i++ ){
                            integral_type mask = (1 << op_bits_amount);
                            for( std::size_t j = 0; j < op_bits_amount; j++){
                                mask >>= 1;
                                op_bits[i][j] = (((rw_trace[i].op & mask) == 0) ? 0 : 1);
                            }
                            std::size_t cur_chunk = 0;
                            // id
                            mask = 0xffff0000;
                            chunks[i][cur_chunk++] = (mask & integral_type(rw_trace[i].id)) >> 16;
                            mask = 0xffff;
                            chunks[i][cur_chunk++] = (mask & integral_type(rw_trace[i].id));

                            // address
                            mask = 0xffff;
                            mask <<= (16 * 9);
                            for( std::size_t j = 0; j < address_chunks_amount; j++){
                                chunks[i][cur_chunk++] = (((mask & integral_type(rw_trace[i].address)) >> (16 * (9-j))));
                                mask >>= 16;
                            }

                            // storage_key
                            mask = 0xffff;
                            mask <<= (16 * 15);
                            for( std::size_t j = 0; j < storage_key_chunks_amount; j++){
                                chunks[i][cur_chunk++] = (((mask & integral_type(rw_trace[i].storage_key)) >> (16 * (15-j))));
                                mask >>= 16;
                            }

                            // rw_id
                            mask = 0xffff;
                            mask <<= 16;
                            chunks[i][cur_chunk++] = (mask & rw_trace[i].rw_id) >> 16;
                            mask >>= 16;
                            chunks[i][cur_chunk++] = (mask & rw_trace[i].rw_id);

                            sorted_prev = sorted;
                            sorted = {op[i]};
                            for( std::size_t j = 0; j < chunks_amount; j++ ){
                                sorted.push_back(chunks[i][j]);
                                if( j == 12 ) sorted.push_back(field_type[i]);
                            }

                            if( i == 0) continue;
                            std::size_t diff_ind;
                            for( diff_ind= 0; diff_ind < chunks_amount; diff_ind++ ){
                                if(sorted[diff_ind] != sorted_prev[diff_ind]) break;
                            }
                            if( op[i] != START_OP && op[i] != PADDING_OP && diff_ind < 30){
                                is_first[i] = 1;
                                if(i != 0) is_last[i-1] = 1;
                            }
                            if( diff_ind > 30 ){
                                value_before_hi[i] = w_hi<FieldType>(rw_trace[i].value_prev);
                                value_before_lo[i] = w_lo<FieldType>(rw_trace[i].value_prev);
                            } else {
                                value_before_hi[i] = value_before_hi[i-1];
                                value_before_lo[i] = value_before_lo[i-1];
                            }
                            mask = (1 << diff_index_bits_amount);
                            for( std::size_t j = 0; j < diff_index_bits_amount; j++){
                                mask >>= 1;
                                diff_index_bits[i][j] = (((diff_ind & mask) == 0) ? 0 : 1);
                            }
                            diff[i] = sorted[diff_ind] - sorted_prev[diff_ind];
                            inv_diff[i] = diff[i] == 0? 0: diff[i].inversed();
                        }
                    } else {
                        std::cout << "Build circuit" << std::endl;
                    }
                    for( std::size_t i = 0; i < max_rw_size - 1; i++){
                        if( i % 50 == 0)  std::cout << "Circuit for " << i << " rows is constructed"  << std::endl;
                        std::size_t cur_column = rw_table_type::get_witness_amount();
                        TYPE op_bit_composition;
                        for( std::size_t j = 0; j < op_bits_amount; j++){
                            allocate(op_bits[i][j], ++cur_column, i);
                            if(j == 0) {
                                op_bit_composition = op_bits[i][j];
                            } else {
                                op_bit_composition *= 2;
                                op_bit_composition += op_bits[i][j];
                            }
                            constrain(op_bits[i][j] * (op_bits[i][j] - 1));
                        };
                        constrain(op_bit_composition - op[i]);

                        for( std::size_t k = 0; k < chunks_amount; k++){
                            allocate(chunks[i][k], ++cur_column, i);
                            lookup(chunks[i][k], "chunk_16_bits/full");
                        }
                        for( std::size_t j = 0; j < diff_index_bits_amount; j++){
                            allocate(diff_index_bits[i][j], ++cur_column, i);
                            constrain(diff_index_bits[i][j] * (diff_index_bits[i][j] - 1));
                        }
                        allocate(value_before_hi[i], ++cur_column, i);
                        allocate(value_before_lo[i], ++cur_column, i);
                        allocate(diff[i], ++cur_column, i); lookup(diff[i], "chunk_16_bits/full");
                        allocate(inv_diff[i], ++cur_column, i);
                        allocate(is_first[i], ++cur_column, i);
                        allocate(is_last[i], ++cur_column, i);
                        allocate(state_root_hi[i], ++cur_column, i);
                        allocate(state_root_lo[i], ++cur_column, i);
                        allocate(state_root_before_hi[i], ++cur_column, i);
                        allocate(state_root_before_lo[i], ++cur_column, i);

                        TYPE id_composition;
                        std::size_t cur_chunk = 0;
                        id_composition = chunks[i][cur_chunk++]; id_composition *= (1<<16);
                        id_composition += chunks[i][cur_chunk++];
                        constrain(id[i] - id_composition);

                        TYPE addr_composition;
                        addr_composition = chunks[i][cur_chunk++]; addr_composition *= (1<<16); //1
                        addr_composition += chunks[i][cur_chunk++]; addr_composition *= (1<<16); //2
                        addr_composition += chunks[i][cur_chunk++]; addr_composition *= (1<<16); //3
                        addr_composition += chunks[i][cur_chunk++]; addr_composition *= (1<<16); //4
                        addr_composition += chunks[i][cur_chunk++]; addr_composition *= (1<<16); //5
                        addr_composition += chunks[i][cur_chunk++]; addr_composition *= (1<<16); //6
                        addr_composition += chunks[i][cur_chunk++]; addr_composition *= (1<<16); //7
                        addr_composition += chunks[i][cur_chunk++]; addr_composition *= (1<<16); //8
                        addr_composition += chunks[i][cur_chunk++]; addr_composition *= (1<<16); //9
                        addr_composition += chunks[i][cur_chunk++];
                        constrain(address[i] - addr_composition);

                        TYPE storage_key_hi_comp;
                        storage_key_hi_comp = chunks[i][cur_chunk++]; storage_key_hi_comp *= (1<<16); //1
                        storage_key_hi_comp += chunks[i][cur_chunk++]; storage_key_hi_comp *= (1<<16); //2
                        storage_key_hi_comp += chunks[i][cur_chunk++]; storage_key_hi_comp *= (1<<16); //3
                        storage_key_hi_comp += chunks[i][cur_chunk++]; storage_key_hi_comp *= (1<<16); //4
                        storage_key_hi_comp += chunks[i][cur_chunk++]; storage_key_hi_comp *= (1<<16); //5
                        storage_key_hi_comp += chunks[i][cur_chunk++]; storage_key_hi_comp *= (1<<16); //6
                        storage_key_hi_comp += chunks[i][cur_chunk++]; storage_key_hi_comp *= (1<<16); //7
                        storage_key_hi_comp += chunks[i][cur_chunk++];
                        constrain(storage_key_hi[i] - storage_key_hi_comp);

                        TYPE storage_key_lo_comp;
                        storage_key_lo_comp = chunks[i][cur_chunk++]; storage_key_lo_comp *= (1<<16); //1
                        storage_key_lo_comp += chunks[i][cur_chunk++]; storage_key_lo_comp *= (1<<16); //2
                        storage_key_lo_comp += chunks[i][cur_chunk++]; storage_key_lo_comp *= (1<<16); //3
                        storage_key_lo_comp += chunks[i][cur_chunk++]; storage_key_lo_comp *= (1<<16); //4
                        storage_key_lo_comp += chunks[i][cur_chunk++]; storage_key_lo_comp *= (1<<16); //5
                        storage_key_lo_comp += chunks[i][cur_chunk++]; storage_key_lo_comp *= (1<<16); //6
                        storage_key_lo_comp += chunks[i][cur_chunk++]; storage_key_lo_comp *= (1<<16); //7
                        storage_key_lo_comp += chunks[i][cur_chunk++];
                        constrain(storage_key_lo[i] - storage_key_lo_comp);

                        TYPE rw_id_composition;
                        rw_id_composition = chunks[i][cur_chunk++]; rw_id_composition *= (1<<16);
                        rw_id_composition += chunks[i][cur_chunk++];
                        constrain(rw_id[i] - rw_id_composition);

                        sorted_prev = sorted;
                        sorted = {op[i]};
                        for( std::size_t j = 0; j < chunks_amount; j++ ){
                            sorted.push_back(chunks[i][j]);
                            if( j == 12 ) sorted.push_back(field_type[i]);
                        }

                        if( i != 0 ){
                            for( std::size_t diff_ind = 0; diff_ind < sorted.size(); diff_ind++ ){
                                TYPE diff_ind_selector = bit_tag_selector<diff_index_bits_amount>(diff_index_bits[i], diff_ind);
                                for(std::size_t less_diff_ind = 0; less_diff_ind < diff_ind; less_diff_ind++){
                                    constrain(diff_ind_selector * (sorted[less_diff_ind]-sorted_prev[less_diff_ind]));
                                }
                                constrain(diff_ind_selector * (sorted[diff_ind] - sorted_prev[diff_ind] - diff[i]));
                            }
                        }

                        TYPE start_selector = bit_tag_selector(op_bits[i], START_OP);
                        TYPE stack_selector = bit_tag_selector(op_bits[i], STACK_OP);
                        TYPE memory_selector = bit_tag_selector(op_bits[i], MEMORY_OP);
                        TYPE storage_selector = bit_tag_selector(op_bits[i], STORAGE_OP);
                        TYPE transient_storage_selector = bit_tag_selector(op_bits[i], TRANSIENT_STORAGE_OP);
                        TYPE call_context_selector = bit_tag_selector(op_bits[i], CALL_CONTEXT_OP);
                        TYPE account_selector = bit_tag_selector(op_bits[i], ACCOUNT_OP);
                        TYPE tx_refund_selector = bit_tag_selector(op_bits[i], TX_REFUND_OP);
                        TYPE tx_access_list_account_selector = bit_tag_selector(op_bits[i], TX_ACCESS_LIST_ACCOUNT_OP);
                        TYPE tx_access_list_account_storage_selector = bit_tag_selector(op_bits[i], TX_ACCESS_LIST_ACCOUNT_STORAGE_OP);
                        TYPE tx_log_selector = bit_tag_selector(op_bits[i], TX_LOG_OP);
                        TYPE tx_receipt_selector = bit_tag_selector(op_bits[i], TX_RECEIPT_OP);
                        TYPE padding_selector = bit_tag_selector(op_bits[i], START_OP);

                        constrain(is_write[i] * (is_write[i]-1));
                        constrain(is_first[i] * (is_first[i]-1));
                        constrain((diff[i] * inv_diff[i] - 1) * diff[i] );
                        constrain((diff[i] * inv_diff[i] - 1) * inv_diff[i] );
                        constrain(is_first[i] * (is_first[i] - 1));
                        constrain(is_last[i] * (is_last[i] - 1));

                        constrain((op[i] - START_OP) * (op[i] - PADDING_OP) * (is_first[i] - 1) * (diff_index_bits[i][0] - 1));
                        constrain((op[i] - START_OP) * (op[i] - PADDING_OP) * (is_first[i] - 1) * (diff_index_bits[i][1] - 1));
                        constrain((op[i] - START_OP) * (op[i] - PADDING_OP) * (is_first[i] - 1) * (diff_index_bits[i][2] - 1));
                        constrain((op[i] - START_OP) * (op[i] - PADDING_OP) * (is_first[i] - 1) * (diff_index_bits[i][3] - 1));
                        if( i != 0 ){
                            constrain((op[i-1] - START_OP) * (op[i-1] - PADDING_OP)
                                * is_last[i-1] * diff_index_bits[i][0]
                                * diff_index_bits[i][1] * diff_index_bits[i][2]
                                * diff_index_bits[i][3]);
                            constrain((op[i] - START_OP) * (op[i] - PADDING_OP) * (is_first[i] - 1) * (value_before_hi[i] - value_before_hi[i-1]));
                            constrain((op[i] - START_OP) * (op[i] - PADDING_OP) * (is_first[i] - 1) * (value_before_lo[i] - value_before_lo[i-1]));
                        }

                        // Specific constraints for START
                        constrain(start_selector);
                        constrain(start_selector * storage_key_hi[i]);
                        constrain(start_selector * storage_key_lo[i]);
                        constrain(start_selector * id[i]);
                        constrain(start_selector * address[i]);
                        constrain(start_selector * field_type[i]);
                        constrain(start_selector * rw_id[i]);
                        constrain(start_selector * value_before_hi[i]);
                        constrain(start_selector * value_before_lo[i]);
                        constrain(start_selector * state_root_hi[i]);
                        constrain(start_selector * state_root_lo[i]);
                        constrain(start_selector * state_root_before_hi[i]);
                        constrain(start_selector * state_root_before_lo[i]);

                        // Specific constraints for STACK
                        constrain(stack_selector * field_type[i]);
                        constrain(stack_selector * is_first[i] * (1 - is_write[i]));  // 4. First stack operation is obviously write
                        if(i!=0) {
                            constrain(stack_selector * (address[i] - address[i-1]) * (is_write[i] - 1));                  // 5. First operation is always write
                            constrain(stack_selector * (address[i] - address[i-1]) * (address[i] - address[i-1] - 1)); // 6. Stack pointer always grows and only by one
                            constrain(stack_selector * (1 - is_first[i]) * (state_root_hi[i] - state_root_before_hi[i-1]));
                            constrain(stack_selector * (1 - is_first[i]) * (state_root_lo[i] - state_root_before_lo[i-1]));
                        }
                        constrain(stack_selector * storage_key_hi[i]);
                        constrain(stack_selector * storage_key_lo[i]);
                        constrain(stack_selector * value_before_hi[i]);
                        constrain(stack_selector * value_before_lo[i]);
                        lookup(stack_selector * address[i], "chunk_16_bits/full");
                        lookup(1023 - stack_selector * address[i], "chunk_16_bits/full");

                        // Specific constraints for MEMORY
                        // address is 32 bit
                        if( i != 0 )  constrain(memory_selector * (is_first[i] - 1) * (is_write[i] - 1) * (value_lo[i] - value_lo[i-1]));       // 4. for read operations value is equal to previous value
                        constrain(memory_selector * value_hi[i]);
                        constrain(memory_selector * is_first[i] * (is_write[i] - 1) * value_lo[i]);
                        constrain(memory_selector * field_type[i]);
                        constrain(memory_selector * storage_key_hi[i]);
                        constrain(memory_selector * storage_key_lo[i]);
                        constrain(memory_selector * value_before_hi[i]);
                        constrain(memory_selector * value_before_lo[i]);
                        constrain(memory_selector * (1 - is_first[i]) * (state_root_hi[i] - state_root_before_hi[i]));
                        constrain(memory_selector * (1 - is_first[i]) * (state_root_lo[i] - state_root_before_lo[i]));
                        lookup(memory_selector * value_lo[i], "chunk_16_bits/full");
                        lookup(255 - memory_selector * value_lo[i], "chunk_16_bits/full");


                        // Specific constraints for STORAGE
                        // lookup to MPT circuit
                        // field is 0
                        constrain(storage_selector * field_type[i]);
                        //lookup_constrain({"MPT table", {
                        //    storage_selector * addr,
                        //    storage_selector * field,
                        //    storage_selector * storage_key_hi,
                        //    storage_selector * storage_key_lo,
                        //    storage_selector * value_before_hi,
                        //    storage_selector * value_before_lo,
                        //    storage_selector * value_hi,
                        //    storage_selector * value_lo,
                        //    storage_selector * state_root_hi,
                        //    storage_selector * state_root_lo
                        //}});

                        // Specific constraints for TRANSIENT_STORAGE
                        // field is 0
                        constrain(transient_storage_selector * field_type[i]);

                        // Specific constraints for CALL_CONTEXT
                        // address, storage_key, initial_value, value_prev are 0
                        // state_root = state_root_prev
                        // range_check for field_flag
                        constrain(call_context_selector * address[i]);
                        constrain(call_context_selector * storage_key_hi[i]);
                        constrain(call_context_selector * storage_key_lo[i]);
                        constrain(call_context_selector * (1 - is_first[i]) * (state_root_hi[i] - state_root_before_hi[i]));
                        constrain(call_context_selector * (1 - is_first[i]) * (state_root_lo[i] - state_root_before_lo[i]));
                        constrain(call_context_selector * value_before_hi[i]);
                        constrain(call_context_selector * value_before_lo[i]);

                        // Specific constraints for ACCOUNT_OP
                        // id, storage_key 0
                        // field_tag -- Range
                        // MPT lookup for last access
                        // value and value_prev consistency
                        constrain(account_selector * id[i]);
                        constrain(account_selector * storage_key_hi[i]);
                        constrain(account_selector * storage_key_lo[i]);
                        //lookup_constrain({"MPT table", {
                        //    storage_selector * is_last * addr,
                        //    storage_selector * is_last * field,
                        //    storage_selector * is_last * storage_key_hi,
                        //    storage_selector * is_last * storage_key_lo,
                        //    storage_selector * is_last * value_before_hi,
                        //    storage_selector * is_last * value_before_lo,
                        //    storage_selector * is_last * value_hi,
                        //    storage_selector * is_last * value_lo,
                        //    storage_selector * is_last * state_root_hi,
                        //    storage_selector * is_last * state_root_lo,
                        //    storage_selector * is_last * state_root_before_hi,
                        //    storage_selector * is_last * state_root_before_lo
                        //}});

                        // Specific constraints for TX_REFUND_OP
                        // address, field_tag and storage_key are 0
                        // state_root eqauls state_root_prev
                        // initial_value is 0
                        // if first access is Read then value = 0
                        constrain(tx_refund_selector * address[i]);
                        constrain(tx_refund_selector * field_type[i]);
                        constrain(tx_refund_selector * storage_key_hi[i]);
                        constrain(tx_refund_selector * storage_key_lo[i]);
                        constrain(tx_refund_selector * is_first[i] * (1-is_write[i]) * value_hi[i]);
                        constrain(tx_refund_selector * is_first[i] * (1-is_write[i]) * value_lo[i]);
                        constrain(tx_refund_selector * (state_root_hi[i] - state_root_before_hi[i]));
                        constrain(tx_refund_selector * (state_root_lo[i] - state_root_before_lo[i]));

                        // Specific constraints for TX_ACCESS_LIST_ACCOUNT_OP
                        // field_tag and storage_key are 0
                        // value is boolean
                        // initial_value is 0
                        // state_root eqauls state_root_prev
                        // value column at previous rotation equals value_prev at current rotation
                        constrain(tx_access_list_account_selector * field_type[i]);
                        constrain(tx_access_list_account_selector * storage_key_hi[i]);
                        constrain(tx_access_list_account_selector * storage_key_lo[i]);
                        constrain(tx_access_list_account_selector * value_hi[i]);
                        constrain(tx_access_list_account_selector * value_lo[i] * (1 - value_lo[i]));
                        constrain(tx_access_list_account_selector * (state_root_hi[i] - state_root_before_hi[i]));
                        constrain(tx_access_list_account_selector * (state_root_lo[i] - state_root_before_lo[i]));
                        if(i != 0) constrain(tx_access_list_account_selector * (1 - is_first[i]) * (value_hi[i-1] - value_before_hi[i]));
                        if(i != 0) constrain(tx_access_list_account_selector * (1 - is_first[i]) * (value_lo[i-1] - value_before_lo[i]));

                        // Specific constraints for TX_ACCESS_LIST_ACCOUNT_STORAGE_OP
                        //    field_tag is 0
                        //    value is boolean
                        //    initial_value is 0
                        //    state_root eqauls state_root_prev
                        //    value column at previous rotation equals value_prev at current rotation
                        constrain(tx_access_list_account_selector * field_type[i]);
                        constrain(tx_access_list_account_selector * value_hi[i]);
                        constrain(tx_access_list_account_selector * value_lo[i] * (1 - value_lo[i]));
                        constrain(tx_access_list_account_selector * (state_root_hi[i] - state_root_before_hi[i]));
                        constrain(tx_access_list_account_selector * (state_root_lo[i] - state_root_before_lo[i]));
                        if(i != 0) constrain(tx_access_list_account_selector * (1 - is_first[i]) * (value_hi[i-1] - value_before_hi[i]));
                        if(i != 0) constrain(tx_access_list_account_selector * (1 - is_first[i]) * (value_lo[i-1] - value_before_lo[i]));


                        // Specific constraints for TX_LOG_OP
                        //  is_write is true
                        //  initial_value is 0
                        //  state_root eqauls state_root_prev
                        //  value_prev equals initial_value
                        //  address 64 bits
                        constrain(tx_log_selector * (1 - is_write[i]));
                        constrain(tx_log_selector * (state_root_hi[i] - state_root_before_hi[i]));
                        constrain(tx_log_selector * (state_root_lo[i] - state_root_before_lo[i]));
                        constrain(tx_log_selector * value_before_hi[i]);
                        constrain(tx_log_selector * value_before_lo[i]);

                        // Specific constraints for TX_RECEIPT_OP
                        // address and storage_key are 0
                        //  field_tag is boolean (according to EIP-658)
                        //  tx_id increases by 1 and value increases as well if tx_id changes
                        //  tx_id is 1 if it's the first row and tx_id is in 11 bits range
                        //  state root is the same
                        //  value_prev is 0 and initial_value is 0
                        constrain(tx_receipt_selector * address[i]);
                        constrain(tx_receipt_selector * storage_key_hi[i]);
                        constrain(tx_receipt_selector * storage_key_lo[i]);

                        // Specific constraints for PADDING
                        constrain(padding_selector * address[i]);
                        constrain(padding_selector * storage_key_hi[i]);
                        constrain(padding_selector * storage_key_lo[i]);
                        constrain(padding_selector * id[i]);
                        constrain(padding_selector * address[i]);
                        constrain(padding_selector * field_type[i]);
                        constrain(padding_selector * rw_id[i]);
                        constrain(padding_selector * state_root_hi[i]);
                        constrain(padding_selector * state_root_lo[i]);
                        constrain(padding_selector * state_root_before_hi[i]);
                        constrain(padding_selector * state_root_before_lo[i]);
                        constrain(padding_selector * value_hi[i]);
                        constrain(padding_selector * value_lo[i]);
                        constrain(padding_selector * value_before_hi[i]);
                        constrain(padding_selector * value_before_lo[i]);
                   }
                }
            };
        }
    }
}