//---------------------------------------------------------------------------//
// Copyright (c) Nil Foundation and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.
//---------------------------------------------------------------------------//

#ifndef EVM_ASSIGNER_LIB_ASSIGNER_INCLUDE_RW_HPP_
#define EVM_ASSIGNER_LIB_ASSIGNER_INCLUDE_RW_HPP_

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/trivial.hpp>

#include <zkevm_word.hpp>

namespace nil {
    namespace evm_assigner {

        template<typename BlueprintFieldType>
        struct rw_operation{
            std::uint8_t op;           // described above
            std::size_t id;            // call_id for stack, memory, tx_id for
            zkevm_word<BlueprintFieldType> address;     // 10 bit for stack, 160 bit for
            std::uint8_t field;          // Not used for stack, memory, storage
            zkevm_word<BlueprintFieldType> storage_key; // 256-bit, not used for stack, memory
            std::size_t rw_id;           // 32-bit
            bool is_write;               // 1 if it's write operation
            zkevm_word<BlueprintFieldType> value;       // It's full 256 words for storage and stack, but it's only byte for memory.
            zkevm_word<BlueprintFieldType> value_prev;

            bool operator< (const rw_operation<BlueprintFieldType> &other) const {
                if( op != other.op ) return op < other.op;
                if( address != other.address ) return address < other.address;
                if( field != other.field ) return field < other.field;
                if( storage_key != other.storage_key ) return storage_key < other.storage_key;
                if( rw_id != other.rw_id) return rw_id < other.rw_id;
                return false;
            }
        };

        constexpr std::uint8_t START_OP = 0;
        constexpr std::uint8_t STACK_OP = 1;
        constexpr std::uint8_t MEMORY_OP = 2;
        constexpr std::uint8_t STORAGE_OP = 3;
        constexpr std::uint8_t TRANSIENT_STORAGE_OP = 4;
        constexpr std::uint8_t CALL_CONTEXT_OP = 5;
        constexpr std::uint8_t ACCOUNT_OP = 6;
        constexpr std::uint8_t TX_REFUND_OP = 7;
        constexpr std::uint8_t TX_ACCESS_LIST_ACCOUNT_OP = 8;
        constexpr std::uint8_t TX_ACCESS_LIST_ACCOUNT_STORAGE_OP = 9;
        constexpr std::uint8_t TX_LOG_OP = 10;
        constexpr std::uint8_t TX_RECEIPT_OP = 11;
        constexpr std::uint8_t PADDING_OP = 12;
        constexpr std::uint8_t rw_options_amount = 13;

        // For testing purposes
        template<typename BlueprintFieldType>
        std::ostream& operator<<(std::ostream& os, const rw_operation<BlueprintFieldType>& obj){
            if(obj.op == START_OP )                           os << "START: ";
            if(obj.op == STACK_OP )                           os << "STACK: ";
            if(obj.op == MEMORY_OP )                          os << "MEMORY: ";
            if(obj.op == STORAGE_OP )                         os << "STORAGE: ";
            if(obj.op == TRANSIENT_STORAGE_OP )               os << "TRANSIENT_STORAGE: ";
            if(obj.op == CALL_CONTEXT_OP )                    os << "CALL_CONTEXT_OP: ";
            if(obj.op == ACCOUNT_OP )                         os << "ACCOUNT_OP: ";
            if(obj.op == TX_REFUND_OP )                       os << "TX_REFUND_OP: ";
            if(obj.op == TX_ACCESS_LIST_ACCOUNT_OP )          os << "TX_ACCESS_LIST_ACCOUNT_OP: ";
            if(obj.op == TX_ACCESS_LIST_ACCOUNT_STORAGE_OP )  os << "TX_ACCESS_LIST_ACCOUNT_STORAGE_OP: ";
            if(obj.op == TX_LOG_OP )                          os << "TX_LOG_OP: ";
            if(obj.op == TX_RECEIPT_OP )                      os << "TX_RECEIPT_OP: ";
            if(obj.op == PADDING_OP )                         os << "PADDING_OP: ";
            os << obj.rw_id << ", addr =" << std::hex << obj.address << std::dec;
            if(obj.op == STORAGE_OP || obj.op == TRANSIENT_STORAGE_OP)
                os << " storage_key = " << obj.storage_key;
            if(obj.is_write) os << " W "; else os << " R ";
            os << "[" << std::hex << obj.value_prev << std::dec <<"] => ";
            os << "[" << std::hex << obj.value << std::dec <<"]";
            return os;
        }

        template<typename BlueprintFieldType>
        rw_operation<BlueprintFieldType> start_operation(){
            return rw_operation<BlueprintFieldType>({START_OP, 0, 0, 0, 0, 0, 0, 0});
        }

        template<typename BlueprintFieldType>
        rw_operation<BlueprintFieldType> stack_operation(std::size_t id, uint16_t address, std::size_t rw_id, bool is_write, zkevm_word<BlueprintFieldType> value){
            assert(id < ( 1 << 28)); // Maximum calls amount(?)
            assert(address < 1024);
            return rw_operation<BlueprintFieldType>({STACK_OP, id, address, 0, 0, rw_id, is_write, value, 0});
        }

        template<typename BlueprintFieldType>
        rw_operation<BlueprintFieldType> memory_operation(std::size_t id, zkevm_word<BlueprintFieldType> address, std::size_t rw_id, bool is_write, zkevm_word<BlueprintFieldType> value){
            assert(id < ( 1 << 28)); // Maximum calls amount(?)
            return rw_operation<BlueprintFieldType>({MEMORY_OP, id, address, 0, 0, rw_id, is_write, value, 0});
        }

        template<typename BlueprintFieldType>
        rw_operation<BlueprintFieldType> storage_operation(
            std::size_t id,
            zkevm_word<BlueprintFieldType> address,
            zkevm_word<BlueprintFieldType> storage_key,
            std::size_t rw_id,
            bool is_write,
            zkevm_word<BlueprintFieldType> value,
            zkevm_word<BlueprintFieldType> value_prev
        ){
            return rw_operation<BlueprintFieldType>({STORAGE_OP, id, address, 0, storage_key, rw_id, is_write, value, value_prev});
        }

        template<typename BlueprintFieldType>
        rw_operation<BlueprintFieldType> padding_operation(){
            return rw_operation<BlueprintFieldType>({PADDING_OP, 0, 0, 0, 0, 0, 0, 0});
        }

        template<typename BlueprintFieldType>
        void process_rw_operations(std::vector<rw_operation<BlueprintFieldType>>& rw_trace,
                                    nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &rw_table) {
            constexpr std::size_t OP = 0;
            constexpr std::size_t ID = 1;
            constexpr std::size_t ADDRESS = 2;
            constexpr std::size_t STORAGE_KEY_HI = 3;
            constexpr std::size_t STORAGE_KEY_LO = 4;
            constexpr std::size_t FIELD_TYPE = 5; // NOT USED FOR STACK, MEMORY and ACCOUNT STORAGE, but used by txComponent.
            constexpr std::size_t RW_ID = 6;
            constexpr std::size_t IS_WRITE = 7;
            constexpr std::size_t VALUE_HI = 8;
            constexpr std::size_t VALUE_LO = 9;

            constexpr std::size_t OP_SELECTORS_AMOUNT = 4; // index \in {0..31}
            constexpr std::array<uint32_t, OP_SELECTORS_AMOUNT> OP_SELECTORS = {10, 11, 12, 13};

            constexpr std::size_t INDICES_AMOUNT = 5; // index \in {0..31}
            constexpr std::array<uint32_t, INDICES_AMOUNT> INDICES = {14, 15, 16, 17, 18};

            constexpr std::size_t IS_FIRST = 19;

            constexpr std::size_t CHUNKS_AMOUNT = 30;
            constexpr std::array<uint32_t, CHUNKS_AMOUNT> CHUNKS = {
                    20, 21, 22, 23, 24, 25, 26,
                27, 28, 29, 30, 31, 32, 33, 34,
                35, 36, 37, 38, 39, 40, 41, 42,
                43, 44, 45, 46, 47, 48, 49
            };

            constexpr std::size_t DIFFERENCE = 50;
            constexpr std::size_t INV_DIFFERENCE = 51;
            constexpr std::size_t VALUE_BEFORE_HI = 52;          // Check, where do we need it.
            constexpr std::size_t VALUE_BEFORE_LO = 53;          // Check, where do we need it.
            constexpr std::size_t STATE_ROOT_HI = 54;            // Check, where do we need it.
            constexpr std::size_t STATE_ROOT_LO = 55;            // Check, where do we need it.
            constexpr std::size_t STATE_ROOT_BEFORE_HI = 56;            // Check, where do we need it.
            constexpr std::size_t STATE_ROOT_BEFORE_LO = 57;            // Check, where do we need it.
            constexpr std::size_t IS_LAST = 58;

            constexpr std::size_t SORTED_COLUMNS_AMOUNT = 32;

            constexpr std::size_t total_witness_amount = 60;

            uint32_t start_row_index = rw_table.witness_column_size(OP);

            BOOST_LOG_TRIVIAL(debug) << "Process RW circuit\n";
            BOOST_LOG_TRIVIAL(debug) << "Start row index: " << start_row_index << "\n";

            std::vector<uint32_t> sorting = {
                OP,
                // ID
                CHUNKS[0], CHUNKS[1],
                // address
                CHUNKS[2], CHUNKS[3], CHUNKS[4], CHUNKS[5], CHUNKS[6],
                CHUNKS[7], CHUNKS[8], CHUNKS[9], CHUNKS[10], CHUNKS[11],
                // field
                FIELD_TYPE,
                // storage_key
                CHUNKS[12], CHUNKS[13], CHUNKS[14], CHUNKS[15], CHUNKS[16],
                CHUNKS[17], CHUNKS[18], CHUNKS[19], CHUNKS[20], CHUNKS[21],
                CHUNKS[22], CHUNKS[23], CHUNKS[24], CHUNKS[25], CHUNKS[26],
                CHUNKS[27],
                // rw_id
                CHUNKS[28], CHUNKS[29]
            };
            //sort operations
            std::sort(rw_trace.begin(), rw_trace.end());

            BOOST_LOG_TRIVIAL(debug) << "Num operations = " << rw_trace.size() << "\n";
            for(uint32_t i = 0; i < rw_trace.size(); i++){
                BOOST_LOG_TRIVIAL(debug) << rw_trace[i] << "\n";
                // Lookup columns
                rw_table.witness(OP, start_row_index + i) = rw_trace[i].op;
                rw_table.witness(ID, start_row_index + i) = rw_trace[i].id;
                rw_table.witness(ADDRESS, start_row_index + i) = rw_trace[i].address.to_field_as_address();
                rw_table.witness(STORAGE_KEY_HI, start_row_index + i) = rw_trace[i].storage_key.w_hi();
                rw_table.witness(STORAGE_KEY_LO, start_row_index + i) = rw_trace[i].storage_key.w_lo();
                rw_table.witness(RW_ID, start_row_index + i) = rw_trace[i].rw_id;
                rw_table.witness(IS_WRITE, start_row_index + i) = rw_trace[i].is_write;
                rw_table.witness(VALUE_HI, start_row_index + i) = rw_trace[i].value.w_hi();
                rw_table.witness(VALUE_LO, start_row_index + i) = rw_trace[i].value.w_lo();

                // Op selectors
                typename BlueprintFieldType::integral_type mask = (1 << OP_SELECTORS_AMOUNT);
                for( std::size_t j = 0; j < OP_SELECTORS_AMOUNT; j++){
                    mask >>= 1;
                    rw_table.witness(OP_SELECTORS[j], start_row_index + i) = (((rw_trace[i].op & mask) == 0) ? 0 : 1);
                }

                // Fill chunks.
                // id
                mask = 0xffff;
                mask <<= 16;
                rw_table.witness(CHUNKS[0], start_row_index + i) = (mask & rw_trace[i].id) >> 16;
                mask >>= 16;
                rw_table.witness(CHUNKS[1], start_row_index + i) = (mask & rw_trace[i].id);

                // address
                mask = 0xffff;
                mask <<= (16 * 9);
                for( std::size_t j = 0; j < 10; j++){
                    rw_table.witness(CHUNKS[2+j], start_row_index + i) = (((rw_trace[i].address & mask) >> (16 * (9-j))));
                    mask >>= 16;
                }

                // storage key
                mask = 0xffff;
                mask <<= (16 * 15);
                for( std::size_t j = 0; j < 16; j++){
                    rw_table.witness(CHUNKS[12+j], start_row_index + i) = (((rw_trace[i].storage_key & mask) >> (16 * (15-j))));
                    mask >>= 16;
                }

                // rw_key
                mask = 0xffff;
                mask <<= 16;
                rw_table.witness(CHUNKS[28], start_row_index + i) = (mask & rw_trace[i].rw_id) >> 16;
                mask >>= 16;
                rw_table.witness(CHUNKS[29], start_row_index + i) = (mask & rw_trace[i].rw_id);

                // fill sorting indices and advices
                if( i == 0 ) continue;
                bool neq = true;
                std::size_t diff_ind = 0;
                for(; diff_ind < sorting.size(); diff_ind++){
                    if(
                        rw_table.witness(sorting[diff_ind], start_row_index+i) !=
                        rw_table.witness(sorting[diff_ind], start_row_index+i - 1)
                    ) break;
                }
                if( diff_ind < 30 ){
                    rw_table.witness(VALUE_BEFORE_HI, start_row_index + i) = rw_trace[i].value_prev.w_hi();
                    rw_table.witness(VALUE_BEFORE_LO, start_row_index + i) = rw_trace[i].value_prev.w_lo();
                } else {
                    rw_table.witness(VALUE_BEFORE_HI, start_row_index + i) = rw_table.witness(VALUE_BEFORE_HI, start_row_index + i - 1);
                    rw_table.witness(VALUE_BEFORE_LO, start_row_index + i) = rw_table.witness(VALUE_BEFORE_LO, start_row_index + i - 1);
                }

                mask = (1 << INDICES_AMOUNT);
                for(std::size_t j = 0; j < INDICES_AMOUNT; j++){
                    mask >>= 1;
                    rw_table.witness(INDICES[j], start_row_index + i) = ((mask & diff_ind) == 0? 0: 1);
                }
                if( rw_trace[i].op != START_OP && diff_ind < 30){
                    rw_table.witness(IS_LAST, start_row_index + i - 1) = 1;
                }
                if( rw_trace[i].op != START_OP && rw_trace[i].op != PADDING_OP && diff_ind < 30){
                    rw_table.witness(IS_FIRST, start_row_index + i) = 1;
                }

                rw_table.witness(DIFFERENCE, start_row_index + i) =
                    rw_table.witness(sorting[diff_ind], start_row_index+i) -
                    rw_table.witness(sorting[diff_ind], start_row_index+i - 1);
                BOOST_LOG_TRIVIAL(debug) << "Diff index = " << diff_ind <<
                    " is_first = " << rw_table.witness(IS_FIRST, start_row_index + i) <<
                    " is_last = " << rw_table.witness(IS_LAST, start_row_index + i) <<
                    "\n";

                if( rw_table.witness(DIFFERENCE, start_row_index + i) == 0)
                    rw_table.witness(INV_DIFFERENCE, start_row_index + i) = 0;
                else
                    rw_table.witness(INV_DIFFERENCE, start_row_index + i) = BlueprintFieldType::value_type::one() / rw_table.witness(DIFFERENCE, start_row_index+i);
            }
        }

    }     // namespace evm_assigner
}    // namespace nil

#endif    // EVM_ASSIGNER_LIB_ASSIGNER_INCLUDE_RW_HPP_
