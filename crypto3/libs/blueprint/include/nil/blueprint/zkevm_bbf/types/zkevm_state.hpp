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
            // Used for all opcodes
            class abstract_zkevm_state{
            public:
                virtual zkevm_word_type stack_top(std::size_t depth = 0) const = 0;
                virtual std::uint8_t    memory(std::size_t addr) const = 0;
                virtual zkevm_word_type storage(zkevm_word_type key) const = 0;
                virtual zkevm_word_type initial_storage(zkevm_word_type key) const = 0;
                virtual std::uint8_t    calldata(std::size_t addr) const = 0;
                virtual std::uint8_t    returndata(std::size_t addr) const = 0;
                virtual zkevm_word_type call_context_value() const = 0;
                virtual std::size_t calldatasize() const = 0;
                virtual std::size_t lastsubcall_id() const = 0;
                virtual std::size_t lastcall_returndata_offset() const = 0;
                virtual std::size_t lastcall_returndata_length() const = 0;
                virtual std::size_t returndatasize() const = 0;
                //virtual std::size_t last_write(state_operation_type op, zkevm_word_type address, std::size_t field, zkevm_word_type key) const = 0;
                virtual std::size_t modified_items_amount() const = 0;
                virtual bool was_accessed(zkevm_word_type address, std::size_t field, zkevm_word_type key) const = 0;
                virtual bool was_written(zkevm_word_type address, std::size_t field, zkevm_word_type key) const = 0;
                virtual std::size_t memory_size() const = 0;
                virtual std::size_t stack_size() const = 0;
                virtual std::size_t rw_counter() const = 0;
                virtual std::size_t gas() const = 0;
                virtual std::size_t pc() const = 0;
                virtual std::size_t opcode() const = 0;
                virtual zkevm_word_type bytecode_hash() const = 0;
                virtual std::size_t call_id() const = 0;
                virtual zkevm_word_type additional_input() const = 0;
                virtual std::size_t block_id() const = 0;
                virtual std::size_t tx_id() const = 0;
                virtual zkevm_word_type call_context_address() const = 0;
                virtual std::size_t depth() const = 0;
                virtual std::size_t bytecode_size() const = 0;
                virtual zkevm_word_type keccak_result() const = 0;
            };

            enum class zkevm_state_word_field: std::size_t {
                storage_key = 0,
                storage_value = 1,
                call_context_address = 2,
                additional_input = 3,
                call_context_value = 4,
                initial_storage_value = 5,
                keccak_result = 6
            };

            enum class zkevm_state_size_t_field: std::size_t {
                calldatasize = 0,
                lastsubcall_id = 1,
                lastcall_returndata_offset = 2,
                lastcall_returndata_length = 3,
                was_accessed = 4,
                was_written = 5,
                depth = 6,
                block_id = 7,
                tx_id = 8,
                returndatasize = 9,
                modified_items_amount = 10,
                bytecode_size = 11
            };

            class zkevm_state : public abstract_zkevm_state{
            protected:
                std::vector<zkevm_word_type> stack;
                std::size_t memory_offset = 0;
                std::vector<std::uint8_t> _memory;
                std::size_t calldata_offset = 0;
                std::vector<std::uint8_t> _calldata;
                std::size_t returndata_offset = 0;
                std::vector<std::uint8_t> _returndata;
                std::map<zkevm_state_word_field, zkevm_word_type> word_fields;
                std::map<zkevm_state_size_t_field, std::size_t> size_t_fields;
                zkevm_word_type _bytecode_hash;
                std::size_t     _opcode;
                std::size_t     _pc;
                std::size_t     _memory_size;
                std::size_t     _stack_size;
                std::size_t     _gas;
                std::size_t     _rw_counter;
                std::size_t     _call_id;
            public:
                zkevm_state(
                    std::size_t     __call_id,
                    zkevm_word_type __bytecode_hash,
                    std::size_t     __pc,
                    std::size_t     __opcode,
                    std::size_t     __stack_size,
                    std::size_t     __memory_size,
                    std::size_t     __gas,
                    std::size_t     __rw_counter
                ):  _bytecode_hash(__bytecode_hash),
                    _opcode(__opcode),
                    _pc(__pc),
                    _memory_size(__memory_size),
                    _stack_size(__stack_size),
                    _gas(__gas),
                    _rw_counter(__rw_counter),
                    _call_id(__call_id)
                {}
                void load_stack(const std::vector<zkevm_word_type> &_stack, std::size_t depth){
                    BOOST_ASSERT(stack.size() == 0);
                    if( depth > _stack.size() )
                        stack = _stack;
                    else
                        stack.insert(stack.end(), _stack.end() - depth, _stack.end());
                }
                void load_memory(const std::vector<std::uint8_t> &_mem, std::size_t offset, std::size_t length){
                    BOOST_ASSERT(_memory.size() == 0);
                    memory_offset = offset;
                    if( offset >= _mem.size() ) {
                        _memory.resize(length, 0);
                        return;
                    }
                    _memory.insert(_memory.end(), _mem.begin() + offset, _mem.begin() + std::min(_mem.size(), offset + length));
                    if( _mem.size() < offset + length){
                        _memory.resize(offset + length, 0);
                    }
                }
                void load_calldata(const std::vector<std::uint8_t> &_cdata, std::size_t offset, std::size_t length){
                    BOOST_ASSERT(_calldata.size() == 0);
                    _calldata.resize(length, 0);

                    calldata_offset = offset;
                    if( offset >= _cdata.size() ) return;

                    for(std::size_t i = 0; i < std::min(_cdata.size() - offset, length); i++ )
                        _calldata[i] = _cdata[offset+i];
                }

                void load_returndata(const std::vector<std::uint8_t> &_rdata, std::size_t offset, std::size_t length){
                    BOOST_ASSERT(_returndata.size() == 0);
                    _returndata.resize(length, 0);

                    returndata_offset = offset;
                    if( offset >= _rdata.size() ) return;

                    for(std::size_t i = 0; i < std::min(_rdata.size() - offset, length); i++ )
                        _returndata[i] = _rdata[offset+i];
                }

                void load_word_field(zkevm_state_word_field k, zkevm_word_type v){
                    BOOST_ASSERT( word_fields.count(k) == 0);
                    word_fields[k] = v;
                }
                void load_size_t_field(zkevm_state_size_t_field k, std::size_t v){
                    BOOST_ASSERT( size_t_fields.count(k) == 0);
                    size_t_fields[k] = v;
                }
                virtual zkevm_word_type stack_top(std::size_t depth = 0) const override{
                    if( depth >= stack.size()){
                        BOOST_LOG_TRIVIAL(fatal) << "Stack depth is out of range! Depth = " << depth << " stack size = " << stack.size();
                    }
                    BOOST_ASSERT( depth < stack.size());
                    return stack.at(stack.size() - 1 - depth);
                }
                virtual zkevm_word_type initial_storage(zkevm_word_type key) const override{
                    BOOST_ASSERT(word_fields.count(zkevm_state_word_field::storage_key));
                    BOOST_ASSERT(word_fields.count(zkevm_state_word_field::initial_storage_value));
                    BOOST_ASSERT(word_fields.at(zkevm_state_word_field::storage_key) == key);
                    return word_fields.at(zkevm_state_word_field::initial_storage_value);
                }
                virtual zkevm_word_type storage(zkevm_word_type key) const override{
                    BOOST_ASSERT(word_fields.count(zkevm_state_word_field::storage_key));
                    BOOST_ASSERT(word_fields.count(zkevm_state_word_field::storage_value));
                    BOOST_ASSERT(word_fields.at(zkevm_state_word_field::storage_key) == key);
                    return word_fields.at(zkevm_state_word_field::storage_value);
                }

                virtual zkevm_word_type keccak_result() const override{
                    BOOST_ASSERT(word_fields.count(zkevm_state_word_field::keccak_result));
                    return word_fields.at(zkevm_state_word_field::keccak_result);
                }

                virtual std::uint8_t memory(std::size_t addr) const override{
                    if( addr < memory_offset) {
                        BOOST_LOG_TRIVIAL(fatal) << "Memory address is out of range! Address = " << addr << " memory_offset = " << memory_offset;
                    }
                    if( addr >= memory_offset + _memory.size()){
                        BOOST_LOG_TRIVIAL(fatal) << "Memory address is out of range! Address = " << addr << " memory_offset = " << memory_offset << " memory_size = " << _memory.size();
                    }
                    BOOST_ASSERT( addr >= memory_offset && addr < memory_offset + _memory.size());
                    return _memory.at(addr - memory_offset);
                }
                virtual std::uint8_t calldata(std::size_t addr) const override{
                    BOOST_ASSERT( addr >= calldata_offset && addr < calldata_offset + _calldata.size());
                    return _calldata.at(addr - calldata_offset);
                }
                virtual std::uint8_t returndata(std::size_t addr) const override{
                    BOOST_ASSERT( addr >= returndata_offset && addr < returndata_offset + _returndata.size());
                    return _returndata.at(addr - returndata_offset);
                }
                virtual std::size_t calldatasize() const override{
                    BOOST_ASSERT( size_t_fields.count(zkevm_state_size_t_field::calldatasize) );
                    return size_t_fields.at(zkevm_state_size_t_field::calldatasize);
                }
                virtual zkevm_word_type call_context_value() const override{
                    BOOST_ASSERT( word_fields.count(zkevm_state_word_field::call_context_value) );
                    return word_fields.at(zkevm_state_word_field::call_context_value);
                }
                virtual std::size_t lastsubcall_id() const override{
                    BOOST_ASSERT( size_t_fields.count(zkevm_state_size_t_field::lastsubcall_id) );
                    return size_t_fields.at(zkevm_state_size_t_field::lastsubcall_id);
                }
                virtual std::size_t lastcall_returndata_offset() const override{
                    BOOST_ASSERT( size_t_fields.count(zkevm_state_size_t_field::lastcall_returndata_offset) );
                    return size_t_fields.at(zkevm_state_size_t_field::lastcall_returndata_offset);
                }
                virtual std::size_t lastcall_returndata_length() const override{
                    BOOST_ASSERT( size_t_fields.count(zkevm_state_size_t_field::lastcall_returndata_length) );
                    return size_t_fields.at(zkevm_state_size_t_field::lastcall_returndata_length);
                }
                virtual std::size_t returndatasize() const override{
                    BOOST_ASSERT( size_t_fields.count(zkevm_state_size_t_field::returndatasize) );
                    return size_t_fields.at(zkevm_state_size_t_field::returndatasize);
                }
                //virtual std::size_t last_write(state_operation_type op, zkevm_word_type address, std::size_t field, zkevm_word_type key) const = 0;
                virtual std::size_t modified_items_amount() const override{
                    BOOST_ASSERT( size_t_fields.count(zkevm_state_size_t_field::modified_items_amount) );
                    return size_t_fields.at(zkevm_state_size_t_field::modified_items_amount);
                }
                virtual bool was_accessed(zkevm_word_type address, std::size_t field, zkevm_word_type key) const override{
                    BOOST_ASSERT(word_fields.at(zkevm_state_word_field::storage_key) == key);
                    BOOST_ASSERT(word_fields.at(zkevm_state_word_field::call_context_address) == address);
                    BOOST_ASSERT( size_t_fields.count(zkevm_state_size_t_field::was_accessed) );
                    return size_t_fields.at(zkevm_state_size_t_field::was_accessed);
                }
                virtual bool was_written(zkevm_word_type address, std::size_t field, zkevm_word_type key) const override{
                    BOOST_ASSERT( size_t_fields.count(zkevm_state_size_t_field::was_written) );
                    return size_t_fields.at(zkevm_state_size_t_field::was_written);
                }
                virtual std::size_t memory_size() const override{
                    return _memory_size;
                }
                virtual std::size_t stack_size() const override{
                    return _stack_size;
                }
                virtual std::size_t rw_counter() const override{
                    return _rw_counter;
                }
                virtual std::size_t gas() const override{
                    return _gas;
                }
                virtual std::size_t pc() const override{
                    return _pc;
                }
                virtual std::size_t opcode() const override{
                    return _opcode;
                }
                virtual zkevm_word_type bytecode_hash() const override{
                    return _bytecode_hash;
                }
                virtual std::size_t call_id() const override{
                    return _call_id;
                }
                virtual zkevm_word_type additional_input() const override{
                    BOOST_ASSERT(word_fields.count(zkevm_state_word_field::additional_input));
                    return word_fields.at(zkevm_state_word_field::additional_input);
                }
                virtual std::size_t block_id() const override{
                    BOOST_ASSERT( size_t_fields.count(zkevm_state_size_t_field::block_id) );
                    return size_t_fields.at(zkevm_state_size_t_field::block_id);
                }
                virtual std::size_t tx_id() const override{
                    BOOST_ASSERT( size_t_fields.count(zkevm_state_size_t_field::tx_id) );
                    return size_t_fields.at(zkevm_state_size_t_field::tx_id);
                }
                virtual zkevm_word_type call_context_address() const override{
                    BOOST_ASSERT(word_fields.count(zkevm_state_word_field::call_context_address));
                    return word_fields.at(zkevm_state_word_field::call_context_address);
                }
                virtual std::size_t depth() const override{
                    BOOST_ASSERT( size_t_fields.count(zkevm_state_size_t_field::depth) );
                    return size_t_fields.at(zkevm_state_size_t_field::depth);
                }
                virtual std::size_t bytecode_size() const override{
                    BOOST_ASSERT( size_t_fields.count(zkevm_state_size_t_field::bytecode_size) );
                    return size_t_fields.at(zkevm_state_size_t_field::bytecode_size);
                }
            };
        } // namespace bbf
    } // namespace blueprint
} // namespace nil
