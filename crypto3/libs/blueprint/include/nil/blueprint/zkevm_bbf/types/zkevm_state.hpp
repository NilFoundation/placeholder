//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova   <e.tatuzova@nil.foundation>
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
#include <nil/crypto3/hash/type_traits.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/blueprint/components/hashes/keccak/util.hpp> //Move needed utils to bbf
#include <nil/blueprint/bbf/generic.hpp>

#include <nil/blueprint/zkevm_bbf/types/zkevm_word.hpp>
#include <nil/blueprint/zkevm_bbf/types/opcode_enum.hpp>


namespace nil {
    namespace blueprint {
        namespace bbf {
            // zkevm_state that is used for all opcodes
            struct basic_zkevm_state_part {
                std::size_t     call_id = 0;            // RW counter on start_call
                zkevm_word_type bytecode_hash = 0;
                std::size_t     opcode = 0;
                std::size_t     pc = 0;
                std::size_t     stack_size = 0;         // BEFORE opcode
                std::size_t     memory_size = 0;        // BEFORE opcode
                std::size_t     rw_counter = 0;
                std::size_t     gas = 0;

                std::vector<zkevm_word_type>            stack_slice; // BEFORE opcode
            };

            struct call_header_zkevm_state_part {
                std::size_t     block_id;               // RW counter on start_block
                std::size_t     tx_id;                  // RW counter on start_transaction
                zkevm_word_type block_hash;
                zkevm_word_type tx_hash;
                zkevm_word_type call_context_address;   // tx_to for transaction depends on CALL/DELEGATECALL opcodes
                std::size_t     depth;

                std::vector<std::uint8_t> calldata;
            };

            struct call_context_zkevm_state_part {
                std::vector<std::uint8_t>   lastcall_returndata_slice; // BEFORE opcode
                std::size_t                 lastcall_returndataoffset;
                std::size_t                 lastcall_returndatalength;
                std::size_t                 lastcall_id;
            };

            struct world_state_zkevm_state_part{
                std::map<zkevm_word_type, zkevm_word_type>  storage_slice; // BEFORE opcode
                std::size_t     modified_items;
                std::map<std::tuple<rw_operation_type, zkevm_word_type, std::size_t, zkevm_word_type>, std::size_t>  last_write_rw_counter; // BEFORE opcode
                std::set<std::tuple<zkevm_word_type, std::size_t, zkevm_word_type>> was_accessed; // For SLOAD, SSTORE gas proving
                std::set<std::tuple<zkevm_word_type, std::size_t, zkevm_word_type>> was_written;
            };

            // Used for all opcodes
            class zkevm_state{
            protected:
                // helpers for data access control
                bool            is_push;
                bool            needs_memory;
                bool            needs_world_state_access;
                bool            needs_call_header_access;
                bool            needs_call_context_access;

                basic_zkevm_state_part base;
                call_header_zkevm_state_part call_header;
                call_context_zkevm_state_part call_context;
                world_state_zkevm_state_part   world_state;

                zkevm_word_type _additional_input;       // data for pushX opcode
                std::map<std::size_t, std::uint8_t>         memory_slice; // BEFORE opcode
            public:
                zkevm_word_type stack_top(std::size_t depth = 0) const{
                    BOOST_ASSERT(depth < base.stack_slice.size());
                    return base.stack_slice[base.stack_slice.size() - 1 - depth];
                }

                zkevm_word_type memory(std::size_t addr) const{
                    BOOST_ASSERT(needs_memory);
                    if( memory_slice.find(addr) == memory_slice.end() )
                        return 0;
                    else
                        return memory_slice.at(addr);
                }

                zkevm_word_type storage(zkevm_word_type key) const{
                    BOOST_ASSERT(needs_world_state_access);
                    if( world_state.storage_slice.find(key) == world_state.storage_slice.end() )
                        return 0;
                    else
                        return world_state.storage_slice.at(key);
                }

                zkevm_word_type calldata(std::size_t addr) const{
                    BOOST_ASSERT(needs_call_header_access);
                    if( addr < call_header.calldata.size() )
                        return call_header.calldata[addr];
                    else
                        return 0;
                }

                zkevm_word_type returndata(std::size_t addr) const{
                    BOOST_ASSERT(needs_call_context_access);
                    if( addr < call_context.lastcall_returndata_slice.size() )
                        return call_context.lastcall_returndata_slice[addr];
                    else
                        return 0;

                }

                std::size_t calldatasize() const{
                    BOOST_ASSERT(needs_call_header_access);
                    return call_header.calldata.size();
                }

                std::size_t lastcall_returndata_offset() const{
                    BOOST_ASSERT(needs_call_context_access);
                    return call_context.lastcall_returndataoffset;
                }

                std::size_t lastcall_returndata_length() const{
                    BOOST_ASSERT(needs_call_context_access);
                    return call_context.lastcall_returndatalength;
                }

                std::size_t returndatasize() const{
                    BOOST_ASSERT(needs_call_context_access);
                    return call_context.lastcall_returndata_slice.size();
                }

                std::size_t last_write(rw_operation_type op, zkevm_word_type address, std::size_t field, zkevm_word_type key) const{
                    BOOST_ASSERT(needs_world_state_access);
                    if( world_state.last_write_rw_counter.find(std::make_tuple(op, address, field, key)) == world_state.last_write_rw_counter.end() )
                        return 0;
                    return world_state.last_write_rw_counter.at(std::make_tuple(op, address, field, key));
                }

                std::size_t modified_items_amount() const{
                    BOOST_ASSERT(needs_world_state_access);
                    return world_state.modified_items;
                }

                bool was_accessed(zkevm_word_type address, std::size_t field, zkevm_word_type key) const{
                    BOOST_ASSERT(needs_world_state_access);
                    return world_state.was_accessed.contains(std::make_tuple(address, field, key));
                }

                bool was_written(zkevm_word_type address, std::size_t field, zkevm_word_type key) const{
                    BOOST_ASSERT(needs_world_state_access);
                    return world_state.was_written.contains(std::make_tuple(address, field, key));
                }

                std::size_t lastsubcall_id() const{
                    BOOST_ASSERT(needs_call_context_access);
                    return call_context.lastcall_id;
                }

                std::size_t memory_size() const{
                    return base.memory_size;
                }

                std::size_t stack_size() const{
                    return base.stack_size;
                }

                std::size_t rw_counter() const{
                    return base.rw_counter;
                }

                std::size_t gas() const{
                    return base.gas;
                }

                std::size_t pc() const{
                    return base.pc;
                }

                std::size_t opcode() const{
                    return base.opcode;
                }

                zkevm_word_type bytecode_hash() const{
                    return base.bytecode_hash;
                }

                std::size_t call_id() const{
                    return base.call_id;
                }

                zkevm_word_type additional_input() const{
                    BOOST_ASSERT(is_push);
                    return _additional_input;
                }

                std::size_t block_id() const{
                    BOOST_ASSERT(needs_call_header_access);
                    return call_header.block_id;
                }

                std::size_t tx_id() const{
                    BOOST_ASSERT(needs_call_header_access);
                    return call_header.tx_id;
                }

                zkevm_word_type call_context_address() const{
                    BOOST_ASSERT(needs_call_header_access);
                    return call_header.call_context_address;
                }

                std::size_t depth() const{
                    BOOST_ASSERT(needs_call_header_access);
                    return call_header.depth;
                }

                zkevm_state(const basic_zkevm_state_part &_base):
                    base(_base),
                    is_push(false),
                    needs_memory(false),
                    needs_world_state_access(false),
                    needs_call_header_access(false),
                    needs_call_context_access(false)
                    {}

                zkevm_state(const basic_zkevm_state_part &_base, const call_header_zkevm_state_part &_call_header):
                    base(_base),
                    call_header(_call_header),
                    is_push(false),
                    needs_memory(false),
                    needs_world_state_access(false),
                    needs_call_header_access(true),
                    needs_call_context_access(false){}


                zkevm_state(const basic_zkevm_state_part &_base, zkevm_word_type _add_input):
                    base(_base),
                    _additional_input(_add_input),
                    is_push(true),
                    needs_memory(false),
                    needs_world_state_access(false),
                    needs_call_header_access(false),
                    needs_call_context_access(false) {}

                zkevm_state(const basic_zkevm_state_part &_base, const std::map<size_t, std::uint8_t> &_memory):
                    base(_base),
                    is_push(false),
                    needs_memory(true),
                    needs_world_state_access(false),
                    needs_call_header_access(false),
                    needs_call_context_access(false),
                    memory_slice(_memory) {}

                zkevm_state(const basic_zkevm_state_part &_base, const std::vector<std::uint8_t> &_memory):
                    base(_base),
                    is_push(false),
                    needs_memory(true),
                    needs_world_state_access(false),
                    needs_call_header_access(false),
                    needs_call_context_access(false)
                {
                    for( std::size_t i = 0; i < _memory.size(); i++ ){
                        memory_slice[i] = _memory[i];
                    }
                }

                zkevm_state(const basic_zkevm_state_part &_base, const std::vector<std::uint8_t> _memory,  const call_context_zkevm_state_part &_editable):
                    base(_base),
                    call_context(_editable),
                    is_push(false),
                    needs_memory(true),
                    needs_world_state_access(false),
                    needs_call_header_access(false),
                    needs_call_context_access(true)
                {
                    for( std::size_t i = 0; i < _memory.size(); i++ ){
                        memory_slice[i] = _memory[i];
                    }
                }

                zkevm_state(
                    const basic_zkevm_state_part &_base,
                    const call_header_zkevm_state_part &_call_header,
                    const world_state_zkevm_state_part &_world_state
                ): base(_base),
                   call_header(_call_header),
                   world_state(_world_state),
                   is_push(false),
                   needs_memory(false),
                   needs_world_state_access(true),
                   needs_call_header_access(true),
                   needs_call_context_access(false) {}

                zkevm_state(
                    const basic_zkevm_state_part &_base,
                    const call_header_zkevm_state_part &_call_header,
                    const call_context_zkevm_state_part &_call_context,
                    const world_state_zkevm_state_part &_world_state
                ): base(_base),
                    call_header(_call_header),
                    call_context(_call_context),
                    world_state(_world_state),
                    is_push(false),
                    needs_memory(false),
                    needs_world_state_access(true),
                    needs_call_header_access(true),
                    needs_call_context_access(true) {}
            };

            zkevm_state simple_zkevm_state(const basic_zkevm_state_part &_base){
                return zkevm_state(_base);
            }

            zkevm_state push_zkevm_state(const basic_zkevm_state_part &_base, zkevm_word_type additional_input){
                return zkevm_state(_base, additional_input);
            }

            zkevm_state memory_zkevm_state(const basic_zkevm_state_part &_base, std::vector<std::uint8_t> memory){
                return zkevm_state(_base, memory);
            }

            zkevm_state call_header_zkevm_state(const basic_zkevm_state_part &_base, const call_header_zkevm_state_part &_call_header){
                return zkevm_state(_base, _call_header);
            }

            zkevm_state returndata_zkevm_state(
                const basic_zkevm_state_part &_base,
                const std::vector<std::uint8_t> &memory,
                const call_context_zkevm_state_part &editable
            ){
                return zkevm_state(_base, memory, editable);
            }

            zkevm_state storage_zkevm_state(
                const basic_zkevm_state_part &_base,
                const call_header_zkevm_state_part &_call_header,
                const world_state_zkevm_state_part &_world_state
            ){
                return zkevm_state(_base, _call_header, _world_state);
            }

            zkevm_state start_block_zkevm_state(zkevm_word_type block_hash, std::size_t block_id){
                basic_zkevm_state_part base;
                call_header_zkevm_state_part call_header;
                base.call_id = block_id;
                base.opcode = opcode_to_number(zkevm_opcode::start_block);// BEFORE opcode
                base.rw_counter = block_id;
                call_header.block_id = block_id;
                call_header.block_hash = block_hash;
                return zkevm_state(base, call_header);
            }

            zkevm_state end_block_zkevm_state(std::size_t block_id, std::size_t rw_counter){
                basic_zkevm_state_part base;
                base.call_id = block_id;
                base.opcode = opcode_to_number(zkevm_opcode::end_block);// BEFORE opcode
                base.rw_counter = rw_counter;
                return zkevm_state(base);
            }

            zkevm_state end_call_zkevm_state(
                basic_zkevm_state_part base,
                call_header_zkevm_state_part call_header,
                call_context_zkevm_state_part call_context,
                world_state_zkevm_state_part   world_state
            ){
                return zkevm_state(base, call_header, call_context, world_state);
            }

            template <typename FieldType, GenerationStage stage>
            struct state_vars{
                using TYPE = typename generic_component<FieldType, stage>::TYPE;

                TYPE call_id;
                TYPE bytecode_hash_hi;
                TYPE bytecode_hash_lo;
                TYPE pc;
                TYPE opcode;
                TYPE gas_hi;
                TYPE gas_lo;
                TYPE stack_size;
                TYPE memory_size;
                TYPE rw_counter;

                TYPE row_counter;
                TYPE step_start;
                TYPE row_counter_inv;
                TYPE opcode_parity;
                TYPE is_even;

                static std::size_t get_items_amout(){ return 15; }
            };

            template <typename FieldType>
            class zkevm_state_vars{
            public:
                using TYPE = typename generic_component<FieldType, GenerationStage::CONSTRAINTS>::TYPE;

                zkevm_state_vars(const std::vector<state_vars<FieldType, GenerationStage::CONSTRAINTS>> &_states, std::size_t size){
                    state.assign(_states.begin()+1, _states.begin() + size + 2);
                }
                TYPE tx_hash(std::size_t row) const{
                    BOOST_ASSERT(row < state.size() - 1);
                    return state[row].tx_hash;
                }   // full transaction hash. Now it is not used. But it’ll be used some day
                TYPE call_id(std::size_t row) const{
                    BOOST_ASSERT(row < state.size() - 1);
                    return state[row].call_id;
                }   // call_id — number of current transaction in block
                TYPE pc(std::size_t row) const{
                    //BOOST_ASSERT(row < state.size() - 1);
                    return state[row].pc;
                }
                TYPE gas(std::size_t row) const{
                    BOOST_ASSERT(row < state.size() - 1);
                    return state[row].gas_hi * 0x10000 + state[row].gas_lo;
                }
                TYPE rw_counter(std::size_t row) const{
                    BOOST_ASSERT(row < state.size() - 1);
                    return state[row].rw_counter;
                }
                TYPE bytecode_hash_hi(std::size_t row) const{
                    BOOST_ASSERT(row < state.size() - 1);
                    return state[row].bytecode_hash_hi;
                }
                TYPE bytecode_hash_lo(std::size_t row) const{
                    BOOST_ASSERT(row < state.size() - 1);
                    return state[row].bytecode_hash_lo;
                }
                TYPE opcode(std::size_t row) const{
                    BOOST_ASSERT(row < state.size() - 1);
                    return state[row].opcode;
                }
                TYPE additional_input(std::size_t row) const{
                    BOOST_ASSERT(row < state.size() - 1);
                    return state[row].additional_input;
                } // data for pushX opcode
                TYPE stack_size(std::size_t row) const{
                    BOOST_ASSERT(row < state.size() - 1);
                    return state[row].stack_size;
                }       // BEFORE opcode
                TYPE memory_size(std::size_t row) const{
                    BOOST_ASSERT(row < state.size() - 1);
                    return state[row].memory_size;
                }      // BEFORE opcode
                TYPE tx_finish(std::size_t row) const{
                    BOOST_ASSERT(row < state.size() - 1);
                    return state[row].tx_finish;
                }       // convinent, but optional11.

                TYPE tx_hash_next() const{
                    return state[state.size()-1].tx_hash;
                } // full transaction hash. Now it is not used. But it’ll be used some day
                TYPE call_id_next() const{
                    return state[state.size()-1].call_id;
                } // call_id — number of current transaction in block
                TYPE pc_next() const{
                    return state[state.size()-1].pc;
                }
                TYPE gas_next() const{
                    return state[state.size()-1].gas_hi * 0x10000 + state[state.size()-1].gas_lo;;
                }
                TYPE rw_counter_next() const{
                    return state[state.size()-1].rw_counter;
                }
                TYPE bytecode_hash_hi_next() const{
                    return state[state.size()-1].bytecode_hash_hi;
                }
                TYPE bytecode_hash_lo_next() const{
                    return state[state.size()-1].bytecode_hash_lo;
                }
                TYPE opcode_next() const{
                    return state[state.size()-1].opcode;
                }
                TYPE stack_size_next() const{
                    return state[state.size()-1].stack_size;
                }       // BEFORE opcode
                TYPE memory_size_next() const{
                    return state[state.size()-1].memory_size;
                }      // BEFORE opcode
            protected:
                std::vector<state_vars<FieldType, GenerationStage::CONSTRAINTS>> state;
            };
        } // namespace bbf
    } // namespace blueprint
} // namespace nil
