// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <iostream>
#include <algorithm>
#include "eof.hpp"
#include "execution_state.hpp"
#include "instructions_traits.hpp"
#include "instructions_xmacro.hpp"
#include <ethash/keccak.hpp>

namespace evmone
{
using code_iterator = const uint8_t*;

/// Represents the pointer to the stack top item
/// and allows retrieving stack items and manipulating the pointer.
template<typename BlueprintFieldType>
class StackTop
{
    nil::evm_assigner::zkevm_word<BlueprintFieldType>* m_top;

public:
    StackTop(nil::evm_assigner::zkevm_word<BlueprintFieldType>* top) noexcept : m_top{top} {}

    /// Returns the reference to the stack item by index, where 0 means the top item
    /// and positive index values the items further down the stack.
    /// Using [-1] is also valid, but .push() should be used instead.
    [[nodiscard]] nil::evm_assigner::zkevm_word<BlueprintFieldType>& operator[](int index) noexcept { return m_top[-index]; }

    /// Returns the reference to the stack top item.
    [[nodiscard]] nil::evm_assigner::zkevm_word<BlueprintFieldType>& top() noexcept { return *m_top; }

    /// Returns the current top item and move the stack top pointer down.
    /// The value is returned by reference because the stack slot remains valid.
    [[nodiscard]] nil::evm_assigner::zkevm_word<BlueprintFieldType>& pop() noexcept { return *m_top--; }

    /// Assigns the value to the stack top and moves the stack top pointer up.
    void push(const nil::evm_assigner::zkevm_word<BlueprintFieldType>& value) noexcept { *++m_top = value; }

    /// size of stack
    uint16_t size(nil::evm_assigner::zkevm_word<BlueprintFieldType>* bottom) noexcept { return (m_top > bottom) ? (uint16_t)(m_top - bottom) : 0; }
};


/// Instruction execution result.
struct Result
{
    evmc_status_code status;
    int64_t gas_left;
};

struct DynStackResult
{
    evmc_status_code status;
    int64_t gas_left;
    int16_t stack_pop{-1};
};

/// Instruction result indicating that execution terminates unconditionally.
struct TermResult : Result
{};

constexpr auto max_buffer_size = std::numeric_limits<uint32_t>::max();

/// The size of the EVM 256-bit word.
constexpr auto word_size = 32;

/// Returns number of words what would fit to provided number of bytes,
/// i.e. it rounds up the number bytes to number of words.
inline constexpr int64_t num_words(uint64_t size_in_bytes) noexcept
{
    return static_cast<int64_t>((size_in_bytes + (word_size - 1)) / word_size);
}

/// Computes gas cost of copying the given amount of bytes to/from EVM memory.
inline constexpr int64_t copy_cost(uint64_t size_in_bytes) noexcept
{
    constexpr auto WordCopyCost = 3;
    return num_words(size_in_bytes) * WordCopyCost;
}

/// Grows EVM memory and checks its cost.
///
/// This function should not be inlined because this may affect other inlining decisions:
/// - making check_memory() too costly to inline,
/// - making mload()/mstore()/mstore8() too costly to inline.
///
/// TODO: This function should be moved to Memory class.
[[gnu::noinline]] inline int64_t grow_memory(
    int64_t gas_left, Memory& memory, uint64_t new_size) noexcept
{
    // This implementation recomputes memory.size(). This value is already known to the caller
    // and can be passed as a parameter, but this make no difference to the performance.

    const auto new_words = num_words(new_size);
    const auto current_words = static_cast<int64_t>(memory.size() / word_size);
    const auto new_cost = 3 * new_words + new_words * new_words / 512;
    const auto current_cost = 3 * current_words + current_words * current_words / 512;
    const auto cost = new_cost - current_cost;

    gas_left -= cost;
    if (gas_left >= 0) [[likely]]
        memory.grow(static_cast<size_t>(new_words * word_size));
    return gas_left;
}

/// The gas cost specification for storage instructions.
struct StorageCostSpec
{
    bool net_cost;        ///< Is this net gas cost metering schedule?
    int16_t warm_access;  ///< Storage warm access cost, YP: G_{warmaccess}
    int16_t set;          ///< Storage addition cost, YP: G_{sset}
    int16_t reset;        ///< Storage modification cost, YP: G_{sreset}
    int16_t clear;        ///< Storage deletion refund, YP: R_{sclear}
};

/// Table of gas cost specification for storage instructions per EVM revision.
/// TODO: This can be moved to instruction traits and be used in other places: e.g.
///       SLOAD cost, replacement for warm_storage_read_cost.
constexpr auto storage_cost_spec = []() noexcept {
    std::array<StorageCostSpec, EVMC_MAX_REVISION + 1> tbl{};

    // Legacy cost schedule.
    for (auto rev : {EVMC_FRONTIER, EVMC_HOMESTEAD, EVMC_TANGERINE_WHISTLE, EVMC_SPURIOUS_DRAGON,
             EVMC_BYZANTIUM, EVMC_PETERSBURG})
        tbl[rev] = {false, 200, 20000, 5000, 15000};

    // Net cost schedule.
    tbl[EVMC_CONSTANTINOPLE] = {true, 200, 20000, 5000, 15000};
    tbl[EVMC_ISTANBUL] = {true, 800, 20000, 5000, 15000};
    tbl[EVMC_BERLIN] = {
        true, instr::warm_storage_read_cost, 20000, 5000 - instr::cold_sload_cost, 15000};
    tbl[EVMC_LONDON] = {
        true, instr::warm_storage_read_cost, 20000, 5000 - instr::cold_sload_cost, 4800};
    tbl[EVMC_PARIS] = tbl[EVMC_LONDON];
    tbl[EVMC_SHANGHAI] = tbl[EVMC_LONDON];
    tbl[EVMC_CANCUN] = tbl[EVMC_LONDON];
    tbl[EVMC_PRAGUE] = tbl[EVMC_LONDON];
    return tbl;
}();


struct StorageStoreCost
{
    int16_t gas_cost;
    int16_t gas_refund;
};

// The lookup table of SSTORE costs by the storage update status.
constexpr auto sstore_costs = []() noexcept {
    std::array<std::array<StorageStoreCost, EVMC_STORAGE_MODIFIED_RESTORED + 1>,
        EVMC_MAX_REVISION + 1>
        tbl{};

    for (size_t rev = EVMC_FRONTIER; rev <= EVMC_MAX_REVISION; ++rev)
    {
        auto& e = tbl[rev];
        if (const auto c = storage_cost_spec[rev]; !c.net_cost)  // legacy
        {
            e[EVMC_STORAGE_ADDED] = {c.set, 0};
            e[EVMC_STORAGE_DELETED] = {c.reset, c.clear};
            e[EVMC_STORAGE_MODIFIED] = {c.reset, 0};
            e[EVMC_STORAGE_ASSIGNED] = e[EVMC_STORAGE_MODIFIED];
            e[EVMC_STORAGE_DELETED_ADDED] = e[EVMC_STORAGE_ADDED];
            e[EVMC_STORAGE_MODIFIED_DELETED] = e[EVMC_STORAGE_DELETED];
            e[EVMC_STORAGE_DELETED_RESTORED] = e[EVMC_STORAGE_ADDED];
            e[EVMC_STORAGE_ADDED_DELETED] = e[EVMC_STORAGE_DELETED];
            e[EVMC_STORAGE_MODIFIED_RESTORED] = e[EVMC_STORAGE_MODIFIED];
        }
        else  // net cost
        {
            e[EVMC_STORAGE_ASSIGNED] = {c.warm_access, 0};
            e[EVMC_STORAGE_ADDED] = {c.set, 0};
            e[EVMC_STORAGE_DELETED] = {c.reset, c.clear};
            e[EVMC_STORAGE_MODIFIED] = {c.reset, 0};
            e[EVMC_STORAGE_DELETED_ADDED] = {c.warm_access, static_cast<int16_t>(-c.clear)};
            e[EVMC_STORAGE_MODIFIED_DELETED] = {c.warm_access, c.clear};
            e[EVMC_STORAGE_DELETED_RESTORED] = {
                c.warm_access, static_cast<int16_t>(c.reset - c.warm_access - c.clear)};
            e[EVMC_STORAGE_ADDED_DELETED] = {
                c.warm_access, static_cast<int16_t>(c.set - c.warm_access)};
            e[EVMC_STORAGE_MODIFIED_RESTORED] = {
                c.warm_access, static_cast<int16_t>(c.reset - c.warm_access)};
        }
    }

    return tbl;
}();

namespace instr::core
{
template <typename BlueprintFieldType>
struct instructions {
    /// Check memory requirements of a reasonable size.
    static bool check_memory(
        int64_t& gas_left, Memory& memory, const nil::evm_assigner::zkevm_word<BlueprintFieldType>& offset, uint64_t size) noexcept
    {
        // TODO: This should be done in intx.
        // There is "branchless" variant of this using | instead of ||, but benchmarks difference
        // is within noise. This should be decided when moving the implementation to intx.
        auto offset_uint = offset.to_uint64();
        if (offset_uint > max_buffer_size)
            return false;

        const auto new_size = offset_uint + size;
        if (new_size > memory.size())
            gas_left = grow_memory(gas_left, memory, new_size);

        return gas_left >= 0;  // Always true for no-grow case.
    }

    /// Check memory requirements for "copy" instructions.
    static bool check_memory(
        int64_t& gas_left, Memory& memory, const nil::evm_assigner::zkevm_word<BlueprintFieldType>& offset, const nil::evm_assigner::zkevm_word<BlueprintFieldType>& size) noexcept
    {
        if (size == 0)  // Copy of size 0 is always valid (even if offset is huge).
            return true;

        // This check has 3 same word checks with the check above.
        // However, compilers do decent although not perfect job unifying common instructions.
        // TODO: This should be done in intx.
        const auto size_uint = size.to_uint64();
        if (size_uint > max_buffer_size)
            return false;

        return check_memory(gas_left, memory, offset, size_uint);
    }
    /// The "core" instruction implementations.
    ///
    /// These are minimal EVM instruction implementations which assume:
    /// - the stack requirements (overflow, underflow) have already been checked,
    /// - the "base" gas const has already been charged,
    /// - the `stack` pointer points to the EVM stack top element.
    /// Moreover, these implementations _do not_ inform about new stack height
    /// after execution. The adjustment must be performed by the caller.
    static void noop(StackTop<BlueprintFieldType> /*stack*/) noexcept {}
    static void pop(StackTop<BlueprintFieldType> /*stack*/) noexcept {}
    static void jumpdest(StackTop<BlueprintFieldType> /*stack*/) noexcept {}

    static TermResult stop_impl(
        StackTop<BlueprintFieldType> /*stack*/, int64_t gas_left, ExecutionState<BlueprintFieldType>& /*state*/, evmc_status_code Status) noexcept
    {
        return {Status, gas_left};
    }
    static TermResult stop(StackTop<BlueprintFieldType> stack, int64_t gas_left, ExecutionState<BlueprintFieldType>& state) noexcept {
        return stop_impl(stack, gas_left, state, EVMC_SUCCESS);
    }

    static TermResult invalid(StackTop<BlueprintFieldType> stack, int64_t gas_left, ExecutionState<BlueprintFieldType>& state) noexcept {
        return stop_impl(stack, gas_left, state, EVMC_INVALID_INSTRUCTION);
    }

    static void add(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id, stack.size(state.stack_space.bottom())-2, state.rw_trace.size(), false, stack[1]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id, stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        const auto& x = stack.pop();
        stack.top() = stack.top() + x;// calculate stack next
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id, stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static void mul(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-2, state.rw_trace.size(), false, stack[1]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        const auto& x = stack.pop();
        stack.top() = stack.top() * x;
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static void sub(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-2, state.rw_trace.size(), false, stack[1]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        const auto& x = stack.pop();
        stack.top() = x - stack.top();
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static void div(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-2, state.rw_trace.size(), false, stack[1]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        const auto& x = stack.pop();
        auto& v = stack[0];
        v = v != 0 ? x / v : 0;
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static void sdiv(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-2, state.rw_trace.size(), false, stack[1]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        const auto& x = stack.pop();
        auto& v = stack[0];
        v = x.sdiv(v);
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static void mod(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-2, state.rw_trace.size(), false, stack[1]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        const auto& x = stack.pop();
        auto& v = stack[0];
        v = v != 0 ? x % v : 0;
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static void smod(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-2, state.rw_trace.size(), false, stack[1]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        const auto& x = stack.pop();
        auto& v = stack[0];
        v = x.smod(v);
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static void addmod(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-3, state.rw_trace.size(), false, stack[2]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-2, state.rw_trace.size(), false, stack[1]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        const auto& x = stack.pop();
        const auto& y = stack.pop();
        auto& m = stack.top();
        m = x.addmod(y, m);
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static void mulmod(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-3, state.rw_trace.size(), false, stack[2]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-2, state.rw_trace.size(), false, stack[1]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        const auto& x = stack[0];
        const auto& y = stack[1];
        auto& m = stack[2];
        m = x.mulmod(y, m);
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static Result exp(StackTop<BlueprintFieldType> stack, int64_t gas_left, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-2, state.rw_trace.size(), false, stack[1]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        const auto& base = stack.pop();
        auto& exponent = stack.top();

        const unsigned exponent_significant_bytes = exponent.count_significant_bytes();
        const unsigned exponent_cost = state.rev >= EVMC_SPURIOUS_DRAGON ? 50 : 10;
        const auto additional_cost = exponent_significant_bytes * exponent_cost;
        if ((gas_left -= additional_cost) < 0)
            return {EVMC_OUT_OF_GAS, gas_left};

        exponent = base.exp(exponent);
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
        return {EVMC_SUCCESS, gas_left};
    }

    static void signextend(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-2, state.rw_trace.size(), false, stack[1]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        const auto& ext = stack.pop();
        auto& x = stack.top();

        if (ext < 31)  // For 31 we also don't need to do anything.
        {
            const auto e = ext.to_uint64();  // uint256 -> uint64.
            const auto sign_word_index =
                static_cast<size_t>(e / sizeof(e));      // Index of the word with the sign bit.
            const auto sign_byte_index = e % sizeof(e);  // Index of the sign byte in the sign word.
            auto sign_word = x.to_uint64(sign_word_index);

            const auto sign_byte_offset = sign_byte_index * 8;
            const auto sign_byte = sign_word >> sign_byte_offset;  // Move sign byte to position 0.

            // Sign-extend the "sign" byte and move it to the right position. Value bits are zeros.
            const auto sext_byte = static_cast<uint64_t>(int64_t{static_cast<int8_t>(sign_byte)});
            const auto sext = sext_byte << sign_byte_offset;

            const auto sign_mask = ~uint64_t{0} << sign_byte_offset;
            const auto value = sign_word & ~sign_mask;  // Reset extended bytes.
            sign_word = sext | value;                   // Combine the result word.

            // Produce bits (all zeros or ones) for extended words. This is done by SAR of
            // the sign-extended byte. Shift by any value 7-63 would work.
            const auto sign_ex = static_cast<uint64_t>(static_cast<int64_t>(sext_byte) >> 8);

            for (size_t i = 3; i > sign_word_index; --i)
                x.set_val(sign_ex, i);  // Clear extended words.
        }
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static void lt(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-2, state.rw_trace.size(), false, stack[1]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        const auto& x = stack.pop();
        stack[0] = x < stack[0];
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static void gt(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-2, state.rw_trace.size(), false, stack[1]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        const auto& x = stack.pop();
        stack[0] = stack[0] < x;  // Arguments are swapped and < is used.
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static void slt(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-2, state.rw_trace.size(), false, stack[1]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        const auto& x = stack.pop();
        stack[0] = x.slt(stack[0]);
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static void sgt(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-2, state.rw_trace.size(), false, stack[1]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        const auto& x = stack.pop();
        stack[0] = stack[0].slt(x);  // Arguments are swapped and SLT is used.
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static void eq(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-2, state.rw_trace.size(), false, stack[1]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        const auto& x = stack.pop();
        stack[0] = stack[0] == x;
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static void iszero(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        stack.top() = stack.top() == 0;
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static void and_(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-2, state.rw_trace.size(), false, stack[1]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        const auto& x = stack.pop();
        stack.top() = stack.top() & x;
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static void or_(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-2, state.rw_trace.size(), false, stack[1]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        const auto& x = stack.pop();
        stack.top() = stack.top() | x;
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static void xor_(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-2, state.rw_trace.size(), false, stack[1]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        const auto& x = stack.pop();
        stack.top() = stack.top() ^ x;
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static void not_(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        stack.top() = ~stack.top();
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static void byte(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-2, state.rw_trace.size(), false, stack[1]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        const auto& n = stack.pop();
        auto& x = stack.top();

        const bool n_valid = n < 32;
        const uint64_t byte_mask = (n_valid ? 0xff : 0);

        const auto index = 31 - static_cast<unsigned>(n.to_uint64() % 32);
        const auto word = x.to_uint64(index / 8);
        const auto byte_index = index % 8;
        const auto byte = (word >> (byte_index * 8)) & byte_mask;
        x = nil::evm_assigner::zkevm_word<BlueprintFieldType>(byte);
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static void shl(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-2, state.rw_trace.size(), false, stack[1]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        const auto& x = stack.pop();
        stack.top() = stack.top() << x;
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static void shr(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-2, state.rw_trace.size(), false, stack[1]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        const auto& x = stack.pop();
        stack.top() = stack.top() >> x;
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static void sar(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-2, state.rw_trace.size(), false, stack[1]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        const auto& y = stack.pop();
        auto& x = stack.top();

        const bool is_neg = x.to_uint64(3) < 0;  // Inspect the top bit (words are LE).
        const nil::evm_assigner::zkevm_word<BlueprintFieldType> sign_mask = is_neg ? 1 : 0;

        const auto mask_shift = (y < 256) ? (256 - y.to_uint64(0)) : 0;
        x = (x >> y) | (sign_mask << mask_shift);
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static Result keccak256(StackTop<BlueprintFieldType> stack, int64_t gas_left, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-2, state.rw_trace.size(), false, stack[1]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        const auto& index = stack.pop();
        auto& size = stack.top();

        if (!check_memory(gas_left, state.memory, index, size))
            return {EVMC_OUT_OF_GAS, gas_left};

        const auto i = index.to_uint64();
        const auto s = size.to_uint64();
        const auto w = num_words(s);
        const auto cost = w * 6;
        if ((gas_left -= cost) < 0)
            return {EVMC_OUT_OF_GAS, gas_left};

        uint8_t* data = nullptr;
        if (s != 0 ) {
            data = &state.memory[i];
            for(uint64_t j = 0; j < 32; j++){
                state.rw_trace.push_back(nil::evm_assigner::memory_operation<BlueprintFieldType>(state.call_id,  index + j, state.rw_trace.size(), false, data[j]));
            }
        }
        size = nil::evm_assigner::zkevm_word<BlueprintFieldType>(ethash::keccak256(data, s));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
        return {EVMC_SUCCESS, gas_left};
    }


    static void address(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        stack.push(nil::evm_assigner::zkevm_word<BlueprintFieldType>(state.msg->recipient));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static Result balance(StackTop<BlueprintFieldType> stack, int64_t gas_left, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        auto& x = stack.top();
        const auto addr = x.to_address();

        if (state.rev >= EVMC_BERLIN && state.host.access_account(addr) == EVMC_ACCESS_COLD)
        {
            if ((gas_left -= instr::additional_cold_account_access_cost) < 0)
                return {EVMC_OUT_OF_GAS, gas_left};
        }

        x = nil::evm_assigner::zkevm_word<BlueprintFieldType>(state.host.get_balance(addr));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
        return {EVMC_SUCCESS, gas_left};
    }

    static void origin(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        stack.push(nil::evm_assigner::zkevm_word<BlueprintFieldType>(state.get_tx_context().tx_origin));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static void caller(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        stack.push(nil::evm_assigner::zkevm_word<BlueprintFieldType>(state.msg->sender));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static void callvalue(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        auto val = nil::evm_assigner::zkevm_word<BlueprintFieldType>(state.msg->value);
        stack.push(val);
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static void calldataload(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        auto& index = stack.top();

        const auto index_uint64 = index.to_uint64();
        if (state.msg->input_size < index_uint64)
            index = 0;
        else
        {
            const auto begin = index_uint64;
            const auto end = std::min(begin + 32, state.msg->input_size);

            uint8_t data[32] = {};
            for (size_t i = 0; i < (end - begin); ++i)
                data[i] = state.msg->input_data[begin + i];

            index = nil::evm_assigner::zkevm_word<BlueprintFieldType>(data, 32);
        }
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static void calldatasize(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        stack.push(state.msg->input_size);
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static Result calldatacopy(StackTop<BlueprintFieldType> stack, int64_t gas_left, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-3, state.rw_trace.size(), false, stack[2]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-2, state.rw_trace.size(), false, stack[1]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        const auto& mem_index = stack.pop();
        const auto& input_index = stack.pop();
        const auto& size = stack.pop();

        if (!check_memory(gas_left, state.memory, mem_index, size))
            return {EVMC_OUT_OF_GAS, gas_left};

        auto dst = mem_index.to_uint64();
        const auto input_index_uint64 = input_index.to_uint64();
        auto src = state.msg->input_size < input_index_uint64 ? state.msg->input_size : input_index_uint64;
        auto s = size.to_uint64();
        auto copy_size = std::min(s, state.msg->input_size - src);

        if (const auto cost = copy_cost(s); (gas_left -= cost) < 0)
            return {EVMC_OUT_OF_GAS, gas_left};

        if (copy_size > 0)
            std::memcpy(&state.memory[dst], &state.msg->input_data[src], copy_size);

        if (s - copy_size > 0)
            std::memset(&state.memory[dst + copy_size], 0, s - copy_size);

        for(uint64_t j = 0; j < copy_size; j++){
            state.rw_trace.push_back(nil::evm_assigner::memory_operation<BlueprintFieldType>(state.call_id,  mem_index + j, state.rw_trace.size(), true, state.memory[dst + j]));
        }

        return {EVMC_SUCCESS, gas_left};
    }

    static void codesize(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        stack.push(state.original_code.size());
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static Result codecopy(StackTop<BlueprintFieldType> stack, int64_t gas_left, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        // TODO: Similar to calldatacopy().
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-3, state.rw_trace.size(), false, stack[2]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-2, state.rw_trace.size(), false, stack[1]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));

        const auto& mem_index = stack.pop();
        const auto& input_index = stack.pop();
        const auto& size = stack.pop();

        if (!check_memory(gas_left, state.memory, mem_index, size))
            return {EVMC_OUT_OF_GAS, gas_left};

        const auto code_size = state.original_code.size();
        const auto dst = mem_index.to_uint64();
        const auto input_index_uint64 = input_index.to_uint64();
        const auto src = code_size < input_index_uint64 ? code_size : input_index_uint64;
        const auto s = size.to_uint64();
        const auto copy_size = std::min(s, code_size - src);

        if (const auto cost = copy_cost(s); (gas_left -= cost) < 0)
            return {EVMC_OUT_OF_GAS, gas_left};

        // TODO: Add unit tests for each combination of conditions.
        if (copy_size > 0)
            std::memcpy(&state.memory[dst], &state.original_code[src], copy_size);

        if (s - copy_size > 0)
            std::memset(&state.memory[dst + copy_size], 0, s - copy_size);

        for(uint64_t j = 0; j < copy_size; j++){
            state.rw_trace.push_back(nil::evm_assigner::memory_operation<BlueprintFieldType>(state.call_id,  mem_index + j, state.rw_trace.size(), true, state.memory[dst + j]));
        }

        return {EVMC_SUCCESS, gas_left};
    }


    static void gasprice(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        stack.push(nil::evm_assigner::zkevm_word<BlueprintFieldType>(state.get_tx_context().tx_gas_price));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static void basefee(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        stack.push(nil::evm_assigner::zkevm_word<BlueprintFieldType>(state.get_tx_context().block_base_fee));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static void blobhash(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        auto& index = stack.top();
        const auto& tx = state.get_tx_context();
        const auto index_uin64 = index.to_uint64();

        index = (index_uin64 < tx.blob_hashes_count) ?
                    nil::evm_assigner::zkevm_word<BlueprintFieldType>(tx.blob_hashes[index_uin64]) :
                    0;
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static void blobbasefee(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        stack.push(nil::evm_assigner::zkevm_word<BlueprintFieldType>(state.get_tx_context().blob_base_fee));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static Result extcodesize(StackTop<BlueprintFieldType> stack, int64_t gas_left, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        auto& x = stack.top();
        const auto addr = x.to_address();

        if (state.rev >= EVMC_BERLIN && state.host.access_account(addr) == EVMC_ACCESS_COLD)
        {
            if ((gas_left -= instr::additional_cold_account_access_cost) < 0)
                return {EVMC_OUT_OF_GAS, gas_left};
        }

        x = state.host.get_code_size(addr);
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
        return {EVMC_SUCCESS, gas_left};
    }

    static Result extcodecopy(StackTop<BlueprintFieldType> stack, int64_t gas_left, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-4, state.rw_trace.size(), false, stack[3]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-3, state.rw_trace.size(), false, stack[2]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-2, state.rw_trace.size(), false, stack[1]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        const auto addr = stack.pop().to_address();
        const auto& mem_index = stack.pop();
        const auto& input_index = stack.pop();
        const auto& size = stack.pop();

        if (!check_memory(gas_left, state.memory, mem_index, size))
            return {EVMC_OUT_OF_GAS, gas_left};

        const auto s = size.to_uint64();
        if (const auto cost = copy_cost(s); (gas_left -= cost) < 0)
            return {EVMC_OUT_OF_GAS, gas_left};

        if (state.rev >= EVMC_BERLIN && state.host.access_account(addr) == EVMC_ACCESS_COLD)
        {
            if ((gas_left -= instr::additional_cold_account_access_cost) < 0)
                return {EVMC_OUT_OF_GAS, gas_left};
        }

        if (s > 0)
        {
            const auto input_index_uint64 = input_index.to_uint64();
            const auto src =
                (max_buffer_size < input_index_uint64) ? max_buffer_size : input_index_uint64;
            const auto dst = mem_index.to_uint64();
            const auto num_bytes_copied = state.host.copy_code(addr, src, &state.memory[dst], s);
            if (const auto num_bytes_to_clear = s - num_bytes_copied; num_bytes_to_clear > 0)
                std::memset(&state.memory[dst + num_bytes_copied], 0, num_bytes_to_clear);
            // TODO: add length write operations to memory
        }

        return {EVMC_SUCCESS, gas_left};
    }

    static void returndatasize(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        stack.push(state.return_data.size());
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static Result returndatacopy(StackTop<BlueprintFieldType> stack, int64_t gas_left, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-3, state.rw_trace.size(), false, stack[2]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-2, state.rw_trace.size(), false, stack[1]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        const auto& mem_index = stack.pop();
        const auto& input_index = stack.pop();
        const auto& size = stack.pop();

        if (!check_memory(gas_left, state.memory, mem_index, size))
            return {EVMC_OUT_OF_GAS, gas_left};

        auto dst = mem_index.to_uint64();
        auto s = size.to_uint64();

        auto src = input_index.to_uint64();
        if (state.return_data.size() < src)
            return {EVMC_INVALID_MEMORY_ACCESS, gas_left};

        if (src + s > state.return_data.size())
            return {EVMC_INVALID_MEMORY_ACCESS, gas_left};

        if (const auto cost = copy_cost(s); (gas_left -= cost) < 0)
            return {EVMC_OUT_OF_GAS, gas_left};

        if (s > 0) {
            std::memcpy(&state.memory[dst], &state.return_data[src], s);
            for(uint64_t j = 0; j < s; j++){
                state.rw_trace.push_back(nil::evm_assigner::memory_operation<BlueprintFieldType>(state.call_id,  dst + j, state.rw_trace.size(), true, state.memory[dst + j]));
            }
        }

        return {EVMC_SUCCESS, gas_left};
    }

    static Result extcodehash(StackTop<BlueprintFieldType> stack, int64_t gas_left, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        auto& x = stack.top();
        const auto addr = x.to_address();

        if (state.rev >= EVMC_BERLIN && state.host.access_account(addr) == EVMC_ACCESS_COLD)
        {
            if ((gas_left -= instr::additional_cold_account_access_cost) < 0)
                return {EVMC_OUT_OF_GAS, gas_left};
        }

        x = nil::evm_assigner::zkevm_word<BlueprintFieldType>(state.host.get_code_hash(addr));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
        return {EVMC_SUCCESS, gas_left};
    }


    static void blockhash(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        auto& number = stack.top();

        const auto upper_bound = state.get_tx_context().block_number;
        const auto lower_bound = std::max(upper_bound - 256, decltype(upper_bound){0});
        const auto n = number.to_uint64();
        const auto header =
            (decltype(upper_bound)(n) < upper_bound && decltype(upper_bound)(n) >= lower_bound) ?
            state.host.get_block_hash(decltype(upper_bound)(n)) : evmc::bytes32{};
        number = nil::evm_assigner::zkevm_word<BlueprintFieldType>(header);
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static void coinbase(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        stack.push(nil::evm_assigner::zkevm_word<BlueprintFieldType>(state.get_tx_context().block_coinbase));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static void timestamp(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        // TODO: Add tests for negative timestamp?
        stack.push(static_cast<uint64_t>(state.get_tx_context().block_timestamp));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static void number(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        // TODO: Add tests for negative block number?
        stack.push(static_cast<uint64_t>(state.get_tx_context().block_number));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static void prevrandao(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        stack.push(nil::evm_assigner::zkevm_word<BlueprintFieldType>(state.get_tx_context().block_prev_randao));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static void gaslimit(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        stack.push(static_cast<uint64_t>(state.get_tx_context().block_gas_limit));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static void chainid(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        stack.push(nil::evm_assigner::zkevm_word<BlueprintFieldType>(state.get_tx_context().chain_id));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static void selfbalance(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        // TODO: introduce selfbalance in EVMC?
        stack.push(nil::evm_assigner::zkevm_word<BlueprintFieldType>(state.host.get_balance(state.msg->recipient)));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    template<typename T>
    static Result mload(StackTop<BlueprintFieldType> stack, int64_t gas_left, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        auto& index = stack.top();

        if (!check_memory(gas_left, state.memory, index, nil::evm_assigner::zkevm_word<BlueprintFieldType>::size))
            return {EVMC_OUT_OF_GAS, gas_left};

        const auto addr = index.to_uint64();
        index = nil::evm_assigner::zkevm_word<BlueprintFieldType>(&state.memory[addr], nil::evm_assigner::zkevm_word<BlueprintFieldType>::size);
        for(uint64_t j = 0; j < nil::evm_assigner::zkevm_word<BlueprintFieldType>::size; j++){
            state.rw_trace.push_back(nil::evm_assigner::memory_operation<BlueprintFieldType>(state.call_id,  addr + j, state.rw_trace.size(), false, state.memory[addr + j]));
        }
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
        return {EVMC_SUCCESS, gas_left};
    }

    template<typename T>
    static Result mstore(StackTop<BlueprintFieldType> stack, int64_t gas_left, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-2, state.rw_trace.size(), false, stack[1]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        const auto& index = stack.pop();
        auto& value = stack.pop();

        if (!check_memory(gas_left, state.memory, index, nil::evm_assigner::zkevm_word<BlueprintFieldType>::size))
            return {EVMC_OUT_OF_GAS, gas_left};

        const auto addr = index.to_uint64();
        value.template store<T>(&state.memory[addr]);
        for(uint64_t j = 0; j < nil::evm_assigner::zkevm_word<BlueprintFieldType>::size; j++){
            state.rw_trace.push_back(nil::evm_assigner::memory_operation<BlueprintFieldType>(state.call_id,  addr + j, state.rw_trace.size(), true, state.memory[addr + j]));
        }
        return {EVMC_SUCCESS, gas_left};
    }

    static Result mstore8(StackTop<BlueprintFieldType> stack, int64_t gas_left, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-2, state.rw_trace.size(), false, stack[1]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        const auto& index = stack.pop();
        const auto& value = stack.pop();

        if (!check_memory(gas_left, state.memory, index, 1))
            return {EVMC_OUT_OF_GAS, gas_left};

        const auto addr = (int)index.to_uint64();
        state.memory[addr] = value.to_uint64();
        for(uint64_t j = 0; j < 8; j++){
            state.rw_trace.push_back(nil::evm_assigner::memory_operation<BlueprintFieldType>(state.call_id,  addr + j, state.rw_trace.size(), true, state.memory[addr + j]));
        }
        return {EVMC_SUCCESS, gas_left};
    }

    /// Internal jump implementation for JUMP/JUMPI instructions.
    static code_iterator jump_impl(ExecutionState<BlueprintFieldType>& state, const nil::evm_assigner::zkevm_word<BlueprintFieldType>& dst) noexcept
    {
        const auto& jumpdest_map = state.analysis.baseline->jumpdest_map;
        const auto dst_uint64 = dst.to_uint64();
        if (dst_uint64 >= jumpdest_map.size() || !jumpdest_map[dst_uint64])
        {
            state.status = EVMC_BAD_JUMP_DESTINATION;
            return nullptr;
        }

        return &state.analysis.baseline->executable_code[dst_uint64];
    }

    /// JUMP instruction implementation using baseline::CodeAnalysis.
    static code_iterator jump(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state, code_iterator /*pos*/) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        return jump_impl(state, stack.pop());
    }

    /// JUMPI instruction implementation using baseline::CodeAnalysis.
    static code_iterator jumpi(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state, code_iterator pos) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-2, state.rw_trace.size(), false, stack[1]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        const auto& dst = stack.pop();
        const auto& cond = stack.pop();
        return cond.to_uint64() > 0 ? jump_impl(state, dst) : pos + 1;
    }

    static code_iterator rjump(StackTop<BlueprintFieldType> /*stack*/, ExecutionState<BlueprintFieldType>& /*state*/, code_iterator pc) noexcept
    {
        // Reading next 2 bytes is guaranteed to be safe by deploy-time validation.
        const auto offset = read_int16_be(&pc[1]);
        return pc + 3 + offset;  // PC_post_rjump + offset
    }

    static code_iterator rjumpi(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state, code_iterator pc) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        const auto cond = stack.pop();
        return cond.to_uint64() > 0 ? rjump(stack, state, pc) : pc + 3;
    }

    static code_iterator rjumpv(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state, code_iterator pc) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        constexpr auto REL_OFFSET_SIZE = sizeof(int16_t);
        const auto case_ = stack.pop();

        const auto max_index = pc[1];
        const auto pc_post = pc + 1 + 1 /* max_index */ + (max_index + 1) * REL_OFFSET_SIZE /* tbl */;

        if (case_.to_uint64() > max_index)
        {
            return pc_post;
        }
        else
        {
            const auto rel_offset =
                read_int16_be(&pc[2 + static_cast<uint16_t>(case_.to_uint64()) * REL_OFFSET_SIZE]);

            return pc_post + rel_offset;
        }
    }

    static code_iterator pc(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state, code_iterator pos) noexcept
    {
        stack.push(static_cast<uint64_t>(pos - state.analysis.baseline->executable_code.data()));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
        return pos + 1;
    }

    static void msize(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        stack.push(state.memory.size());
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static Result gas(StackTop<BlueprintFieldType> stack, int64_t gas_left, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        stack.push(gas_left);
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
        return {EVMC_SUCCESS, gas_left};
    }

    static void tload(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        auto& x = stack.top();
        evmc::bytes32 key = x.to_uint256be();
        const auto value = state.host.get_transient_storage(state.msg->recipient, key);
        // TODO: add trasient storage operations
        x = nil::evm_assigner::zkevm_word<BlueprintFieldType>(value);
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    static Result tstore(StackTop<BlueprintFieldType> stack, int64_t gas_left, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        if (state.in_static_mode())
            return {EVMC_STATIC_MODE_VIOLATION, 0};

        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-2, state.rw_trace.size(), false, stack[1]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        evmc::bytes32 key = stack.pop().to_uint256be();
        evmc::bytes32 value = stack.pop().to_uint256be();
        state.host.set_transient_storage(state.msg->recipient, key, value);
        // TODO: add trasient storage operations
        return {EVMC_SUCCESS, gas_left};
    }

    static void push0(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        stack.push({});
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), true, stack[0]));
    }

    /// PUSH instruction implementation.
    /// @tparam Len The number of push data bytes, e.g. PUSH3 is push<3>.
    ///
    /// It assumes that at lest 32 bytes of data are available so code padding is required.
    template <size_t Len>
    static code_iterator push(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state, code_iterator pos) noexcept
    {
        // TODO size of field in bytes
        constexpr size_t word_size = 8;
        constexpr auto num_full_words = Len / word_size;
        constexpr auto num_partial_bytes = Len % word_size;
        auto data = pos + 1;

        stack.push(0);
        auto& r = stack.top();

        // Load top partial word.
        if constexpr (num_partial_bytes != 0)
        {
            r.load_partial_data(data, num_partial_bytes, num_full_words);
            data += num_partial_bytes;
        }

        // Load full words.
        for (size_t i = 0; i < num_full_words; ++i)
        {
            r.load_partial_data(data, word_size, num_full_words - 1 - i);
            data += word_size;
        }

        int num_words = (int)(Len / nil::evm_assigner::zkevm_word<BlueprintFieldType>::size) + (int)(Len % nil::evm_assigner::zkevm_word<BlueprintFieldType>::size);
        for (int i = 0; i < num_words; ++i) {
            state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  (uint16_t)(stack.size(state.stack_space.bottom())- 1 - i), state.rw_trace.size(), true, stack[i]));
        }

        return pos + (Len + 1);
    }

    /// DUP instruction implementation.
    /// @tparam N  The number as in the instruction definition, e.g. DUP3 is dup<3>.
    template <int N>
    static void dup(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        static_assert(N >= 0 && N <= 16);
        if constexpr (N == 0)
        {
            state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
            const auto index = stack.pop();
            const auto addr = (int)index.to_uint64();
            assert(addr < std::numeric_limits<int>::max());
            state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  (uint16_t)(stack.size(state.stack_space.bottom()) - addr), state.rw_trace.size(), false, stack[addr - 1]));
            stack.push(stack[addr - 1]);
            state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())- 1, state.rw_trace.size(), true, stack[0]));
        }
        else
        {
            state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom()) - N, state.rw_trace.size(), false, stack[N - 1]));
            stack.push(stack[N - 1]);
            state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())- 1, state.rw_trace.size(), true, stack[0]));
        }
    }

    /// SWAP instruction implementation.
    /// @tparam N  The number as in the instruction definition, e.g. SWAP3 is swap<3>.
    template <int N>
    static void swap(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        static_assert(N >= 0 && N <= 16);

        // The simple std::swap(stack.top(), stack[N]) is not used to workaround
        // clang missed optimization: https://github.com/llvm/llvm-project/issues/59116
        // TODO(clang): Check if #59116 bug fix has been released.
        nil::evm_assigner::zkevm_word<BlueprintFieldType>* a;
        uint16_t addr = N;
        if constexpr (N == 0)
        {
            state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
            auto& index = stack.pop();
            assert(index < std::numeric_limits<int>::max());
            addr = (uint16_t)index.to_uint64();
            a = &stack[addr];
        }
        else
        {
            a = &stack[N];
        }
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  (uint16_t)(stack.size(state.stack_space.bottom()) - addr - 1), state.rw_trace.size(), false, stack[addr]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())-1, state.rw_trace.size(), false, stack[0]));
        auto& t = stack.top();
        auto t0 = t.to_uint64(0);
        auto t1 = t.to_uint64(1);
        auto t2 = t.to_uint64(2);
        auto t3 = t.to_uint64(3);
        t = *a;
        a->set_val(t0, 0);
        a->set_val(t1, 1);
        a->set_val(t2, 2);
        a->set_val(t3, 3);
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())- 1, state.rw_trace.size(), true, stack[0]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  (uint16_t)(stack.size(state.stack_space.bottom()) - addr), state.rw_trace.size(), true, stack[addr - 1]));
    }

    static void log(StackTop<BlueprintFieldType> /*stack*/, ExecutionState<BlueprintFieldType>& /*state*/) noexcept {
        // do nothing
    }

    static code_iterator dupn(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state, code_iterator pos) noexcept
    {
        const uint16_t n = pos[1] + 1;

        const uint16_t stack_size = (uint16_t)(&stack.top() - state.stack_space.bottom());

        if (stack_size < n)
        {
            state.status = EVMC_STACK_UNDERFLOW;
            return nullptr;
        }

        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  (uint16_t)(stack.size(state.stack_space.bottom()) - n), state.rw_trace.size(), false, stack[n - 1]));
        stack.push(stack[n - 1]);
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())- 1, state.rw_trace.size(), true, stack[0]));

        return pos + 2;
    }

    static code_iterator swapn(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state, code_iterator pos) noexcept
    {
        const auto n = pos[1] + 1;

        const auto stack_size = &stack.top() - state.stack_space.bottom();

        if (stack_size <= n)
        {
            state.status = EVMC_STACK_UNDERFLOW;
            return nullptr;
        }

        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  (uint16_t)(stack.size(state.stack_space.bottom()) - n - 1), state.rw_trace.size(), false, stack[n]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom()) - 1, state.rw_trace.size(), false, stack[0]));
        // TODO: This may not be optimal, see instr::core::swap().
        std::swap(stack.top(), stack[n]);
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom())- 1, state.rw_trace.size(), true, stack[0]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  (uint16_t)(stack.size(state.stack_space.bottom()) - n - 1), state.rw_trace.size(), true, stack[n]));

        return pos + 2;
    }

    static Result mcopy(StackTop<BlueprintFieldType> stack, int64_t gas_left, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom()) - 3, state.rw_trace.size(), false, stack[2]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom()) - 2, state.rw_trace.size(), false, stack[1]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom()) - 1, state.rw_trace.size(), false, stack[0]));
        const auto& dst_u256 = stack.pop();
        const auto& src_u256 = stack.pop();
        const auto& size_u256 = stack.pop();

        if (!check_memory(gas_left, state.memory, std::max(dst_u256, src_u256), size_u256))
            return {EVMC_OUT_OF_GAS, gas_left};

        const auto dst = dst_u256.to_uint64();
        const auto src = src_u256.to_uint64();
        const auto size = size_u256.to_uint64();

        if (const auto cost = copy_cost(size); (gas_left -= cost) < 0)
            return {EVMC_OUT_OF_GAS, gas_left};

        if (size > 0) {
            std::memmove(&state.memory[dst], &state.memory[src], size);
            // TODO: add length read operations to memory
            // TODO: add length write operations to memory
            /*for(uint64_t j = 0; j < size; j++){
                state.rw_trace.push_back(nil::evm_assigner::memory_operation<BlueprintFieldType>(state.call_id,  src + j, state.rw_trace.size(), false, state.memory[src + j]));
                state.rw_trace.push_back(nil::evm_assigner::memory_operation<BlueprintFieldType>(state.call_id,  dst + j, state.rw_trace.size(), true, state.memory[dst + j]));
            }*/
        }

        return {EVMC_SUCCESS, gas_left};
    }

    static void dataload(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom()) - 1, state.rw_trace.size(), false, stack[0]));
        auto& index = stack.top();

        if (state.data.size() < index.to_uint64())
            index = 0;
        else
        {
            const auto begin = index.to_uint64();
            const auto end = std::min(begin + 32, state.data.size());

            uint8_t data[32] = {};
            for (size_t i = 0; i < (end - begin); ++i)
                data[i] = state.data[begin + i];

            index = nil::evm_assigner::zkevm_word<BlueprintFieldType>(data, (end - begin));
            state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom()) - 1, state.rw_trace.size(), true, stack[0]));
        }
    }

    static void datasize(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        stack.push(state.data.size());
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom()) - 1, state.rw_trace.size(), true, stack[0]));
    }

    static code_iterator dataloadn(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state, code_iterator pos) noexcept
    {
        const auto index = read_uint16_be(&pos[1]);

        stack.push(nil::evm_assigner::zkevm_word<BlueprintFieldType>(&state.data[index], nil::evm_assigner::zkevm_word<BlueprintFieldType>::size));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom()) - 1, state.rw_trace.size(), true, stack[0]));
        return pos + 3;
    }

    static Result datacopy(StackTop<BlueprintFieldType> stack, int64_t gas_left, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom()) - 3, state.rw_trace.size(), false, stack[2]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom()) - 2, state.rw_trace.size(), false, stack[1]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom()) - 1, state.rw_trace.size(), false, stack[0]));
        const auto& mem_index = stack.pop();
        const auto& data_index = stack.pop();
        const auto& size = stack.pop();

        if (!check_memory(gas_left, state.memory, mem_index, size))
            return {EVMC_OUT_OF_GAS, gas_left};

        const auto dst = mem_index.to_uint64();
        // TODO why?
        const auto data_index_uint64 = data_index.to_uint64();
        const auto src =
            state.data.size() < data_index_uint64 ? state.data.size() : data_index_uint64;
        const auto s = size.to_uint64();
        const auto copy_size = std::min(s, state.data.size() - src);

        if (const auto cost = copy_cost(s); (gas_left -= cost) < 0)
            return {EVMC_OUT_OF_GAS, gas_left};

        if (copy_size > 0) {
            std::memcpy(&state.memory[dst], &state.data[src], copy_size);
            for(uint64_t j = 0; j < copy_size; j++){
                state.rw_trace.push_back(nil::evm_assigner::memory_operation<BlueprintFieldType>(state.call_id,  dst + j, state.rw_trace.size(), true, state.memory[dst + j]));
            }
        }

        if (s - copy_size > 0) {
            std::memset(&state.memory[dst + copy_size], 0, s - copy_size);
            for(uint64_t j = 0; j < s - copy_size; j++){
                state.rw_trace.push_back(nil::evm_assigner::memory_operation<BlueprintFieldType>(state.call_id,  dst + j, state.rw_trace.size(), true, 0));
            }
        }

        return {EVMC_SUCCESS, gas_left};
    }

    static Result call_impl(StackTop<BlueprintFieldType> stack, int64_t gas_left, ExecutionState<BlueprintFieldType>& state, Opcode Op) noexcept
    {
        assert(Op == OP_CALL || Op == OP_CALLCODE || Op == OP_DELEGATECALL || Op == OP_STATICCALL);

        uint16_t num_stack_read = (Op == OP_STATICCALL || Op == OP_DELEGATECALL) ? 6 : 7;
        for (uint16_t i = 0; i < num_stack_read; i++) {
            state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  (uint16_t)(stack.size(state.stack_space.bottom()) - (i + 1)), state.rw_trace.size(), false, stack[i]));
        }
        const auto gas = stack.pop();
        const auto dst = stack.pop().to_address();
        const auto value = (Op == OP_STATICCALL || Op == OP_DELEGATECALL) ? 0 : stack.pop();
        const auto has_value = value != 0;
        const auto input_offset_u256 = stack.pop();
        const auto input_size_u256 = stack.pop();
        const auto output_offset_u256 = stack.pop();
        const auto output_size_u256 = stack.pop();

        stack.push(0);  // Assume failure.
        state.return_data.clear();

        if (state.rev >= EVMC_BERLIN && state.host.access_account(dst) == EVMC_ACCESS_COLD)
        {
            if ((gas_left -= instr::additional_cold_account_access_cost) < 0)
                return {EVMC_OUT_OF_GAS, gas_left};
        }

        if (!check_memory(gas_left, state.memory, input_offset_u256, input_size_u256))
            return {EVMC_OUT_OF_GAS, gas_left};

        if (!check_memory(gas_left, state.memory, output_offset_u256, output_size_u256))
            return {EVMC_OUT_OF_GAS, gas_left};

        const auto input_offset = input_offset_u256.to_uint64();
        const auto input_size = input_size_u256.to_uint64();
        const auto output_offset = output_offset_u256.to_uint64();
        const auto output_size = output_size_u256.to_uint64();

        auto msg = evmc_message{};
        msg.kind = (Op == OP_DELEGATECALL) ? EVMC_DELEGATECALL :
                (Op == OP_CALLCODE)     ? EVMC_CALLCODE :
                                            EVMC_CALL;
        msg.flags = (Op == OP_STATICCALL) ? uint32_t{EVMC_STATIC} : state.msg->flags;
        msg.depth = state.msg->depth + 1;
        msg.recipient = (Op == OP_CALL || Op == OP_STATICCALL) ? dst : state.msg->recipient;
        msg.code_address = dst;
        msg.sender = (Op == OP_DELEGATECALL) ? state.msg->sender : state.msg->recipient;
        msg.value =
            (Op == OP_DELEGATECALL) ? state.msg->value : value.to_uint256be();

        if (input_size > 0)
        {
            // input_offset may be garbage if input_size == 0.
            msg.input_data = &state.memory[input_offset];
            msg.input_size = input_size;
        }

        auto cost = has_value ? 9000 : 0;

        if (Op == OP_CALL)
        {
            if (has_value && state.in_static_mode())
                return {EVMC_STATIC_MODE_VIOLATION, gas_left};

            if ((has_value || state.rev < EVMC_SPURIOUS_DRAGON) && !state.host.account_exists(dst))
                cost += 25000;
        }

        if ((gas_left -= cost) < 0)
            return {EVMC_OUT_OF_GAS, gas_left};

        msg.gas = std::numeric_limits<int64_t>::max();
        const auto gas_int64 = (int64_t)gas.to_uint64();
        if (gas_int64 < msg.gas)
            msg.gas = gas_int64;

        if (state.rev >= EVMC_TANGERINE_WHISTLE)  // TODO: Always true for STATICCALL.
            msg.gas = std::min(msg.gas, gas_left - gas_left / 64);
        else if (msg.gas > gas_left)
            return {EVMC_OUT_OF_GAS, gas_left};

        if (has_value)
        {
            msg.gas += 2300;  // Add stipend.
            gas_left += 2300;
        }

        if (state.msg->depth >= 1024)
            return {EVMC_SUCCESS, gas_left};  // "Light" failure.

        if (has_value && nil::evm_assigner::zkevm_word<BlueprintFieldType>(state.host.get_balance(state.msg->recipient)) < value)
            return {EVMC_SUCCESS, gas_left};  // "Light" failure.

        if (Op == OP_DELEGATECALL)
        {
            if (state.rev >= EVMC_PRAGUE && is_eof_container(state.original_code))
            {
                // The code targeted by DELEGATECALL must also be an EOF.
                // This restriction has been added to EIP-3540 in
                // https://github.com/ethereum/EIPs/pull/7131
                uint8_t target_code_prefix[2];
                const auto s = state.host.copy_code(
                    msg.code_address, 0, target_code_prefix, std::size(target_code_prefix));
                if (!is_eof_container({target_code_prefix, s}))
                    return {EVMC_SUCCESS, gas_left};
            }
        }

        const auto result = state.host.call(msg);
        state.return_data.assign(result.output_data, result.output_size);
        stack.top() = result.status_code == EVMC_SUCCESS;
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom()) - 1, state.rw_trace.size(), true, stack[0]));

        if (const auto copy_size = std::min(output_size, result.output_size); copy_size > 0)
            std::memcpy(&state.memory[output_offset], result.output_data, copy_size);

        const auto gas_used = msg.gas - result.gas_left;
        gas_left -= gas_used;
        state.gas_refund += result.gas_refund;
        return {EVMC_SUCCESS, gas_left};
    }

    static Result call(StackTop<BlueprintFieldType> stack, int64_t gas_left, ExecutionState<BlueprintFieldType>& state) noexcept {
        return call_impl(stack, gas_left, state, OP_CALL);
    }

    static Result callcode(StackTop<BlueprintFieldType> stack, int64_t gas_left, ExecutionState<BlueprintFieldType>& state) noexcept {
        return call_impl(stack, gas_left, state, OP_CALLCODE);
    }

    static Result delegatecall(StackTop<BlueprintFieldType> stack, int64_t gas_left, ExecutionState<BlueprintFieldType>& state) noexcept {
        return call_impl(stack, gas_left, state, OP_DELEGATECALL);
    }

    static Result staticcall(StackTop<BlueprintFieldType> stack, int64_t gas_left, ExecutionState<BlueprintFieldType>& state) noexcept {
        return call_impl(stack, gas_left, state, OP_STATICCALL);
    }

    static Result create_impl(StackTop<BlueprintFieldType> stack, int64_t gas_left, ExecutionState<BlueprintFieldType>& state, Opcode Op) noexcept {
        assert(Op == OP_CREATE || Op == OP_CREATE2);

        if (state.in_static_mode())
            return {EVMC_STATIC_MODE_VIOLATION, gas_left};

        uint16_t num_stack_read = (Op == OP_CREATE2) ? 4 : 3;
        for (uint16_t i = 0; i < num_stack_read; i++) {
            state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  (uint16_t)(stack.size(state.stack_space.bottom()) - (i + 1)), state.rw_trace.size(), false, stack[i]));
        }
        const auto endowment = stack.pop();
        const auto init_code_offset_u256 = stack.pop();
        const auto init_code_size_u256 = stack.pop();
        const auto salt = (Op == OP_CREATE2) ? stack.pop() : 0;

        stack.push(0);  // Assume failure.
        state.return_data.clear();

        if (!check_memory(gas_left, state.memory, init_code_offset_u256, init_code_size_u256))
            return {EVMC_OUT_OF_GAS, gas_left};

        const auto init_code_offset = init_code_offset_u256.to_uint64();
        const auto init_code_size = init_code_size_u256.to_uint64();

        if (state.rev >= EVMC_SHANGHAI && init_code_size > 0xC000)
            return {EVMC_OUT_OF_GAS, gas_left};

        const auto init_code_word_cost = 6 * (Op == OP_CREATE2) + 2 * (state.rev >= EVMC_SHANGHAI);
        const auto init_code_cost = num_words(init_code_size) * init_code_word_cost;
        if ((gas_left -= init_code_cost) < 0)
            return {EVMC_OUT_OF_GAS, gas_left};

        if (state.msg->depth >= 1024)
            return {EVMC_SUCCESS, gas_left};  // "Light" failure.

        if (endowment != 0 &&
            nil::evm_assigner::zkevm_word<BlueprintFieldType>(state.host.get_balance(state.msg->recipient)) < endowment)
            return {EVMC_SUCCESS, gas_left};  // "Light" failure.

        auto msg = evmc_message{};
        msg.gas = gas_left;
        if (state.rev >= EVMC_TANGERINE_WHISTLE)
            msg.gas = msg.gas - msg.gas / 64;

        msg.kind = (Op == OP_CREATE) ? EVMC_CREATE : EVMC_CREATE2;
        if (init_code_size > 0)
        {
            // init_code_offset may be garbage if init_code_size == 0.
            msg.input_data = &state.memory[init_code_offset];
            msg.input_size = init_code_size;
        }
        msg.sender = state.msg->recipient;
        msg.depth = state.msg->depth + 1;
        msg.create2_salt = salt.to_uint256be();
        msg.value = endowment.to_uint256be();

        const auto result = state.host.call(msg);
        gas_left -= msg.gas - result.gas_left;
        state.gas_refund += result.gas_refund;

        state.return_data.assign(result.output_data, result.output_size);
        if (result.status_code == EVMC_SUCCESS)
            stack.top() = nil::evm_assigner::zkevm_word<BlueprintFieldType>(result.create_address);
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id,  stack.size(state.stack_space.bottom()) - 1, state.rw_trace.size(), true, stack[0]));

        return {EVMC_SUCCESS, gas_left};
    }

    static Result create(StackTop<BlueprintFieldType> stack, int64_t gas_left, ExecutionState<BlueprintFieldType>& state) noexcept {
        return create_impl(stack, gas_left, state, OP_CREATE);
    }

    static constexpr auto create2(StackTop<BlueprintFieldType> stack, int64_t gas_left, ExecutionState<BlueprintFieldType>& state) noexcept {
        return create_impl(stack, gas_left, state, OP_CREATE2);
    }

    static code_iterator callf(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state, code_iterator pos) noexcept
    {
        const auto index = read_uint16_be(&pos[1]);
        const auto& header = state.analysis.baseline->eof_header;
        const auto stack_size = &stack.top() - state.stack_space.bottom();

        const auto callee_required_stack_size =
            header.types[index].max_stack_height - header.types[index].inputs;
        if (stack_size + callee_required_stack_size > StackSpace<BlueprintFieldType>::limit)
        {
            state.status = EVMC_STACK_OVERFLOW;
            return nullptr;
        }

        if (state.call_stack.size() >= StackSpace<BlueprintFieldType>::limit)
        {
            // TODO: Add different error code.
            state.status = EVMC_STACK_OVERFLOW;
            return nullptr;
        }
        state.call_stack.push_back(pos + 3);

        const auto offset = header.code_offsets[index] - header.code_offsets[0];
        auto code = state.analysis.baseline->executable_code;
        return code.data() + offset;
    }

    static code_iterator retf(StackTop<BlueprintFieldType> /*stack*/, ExecutionState<BlueprintFieldType>& state, code_iterator /*pos*/) noexcept
    {
        const auto p = state.call_stack.back();
        state.call_stack.pop_back();
        return p;
    }

    static code_iterator jumpf(StackTop<BlueprintFieldType> stack, ExecutionState<BlueprintFieldType>& state, code_iterator pos) noexcept
    {
        const auto index = read_uint16_be(&pos[1]);
        const auto& header = state.analysis.baseline->eof_header;
        const auto stack_size = &stack.top() - state.stack_space.bottom();

        const auto callee_required_stack_size =
            header.types[index].max_stack_height - header.types[index].inputs;
        if (stack_size + callee_required_stack_size > StackSpace<BlueprintFieldType>::limit)
        {
            state.status = EVMC_STACK_OVERFLOW;
            return nullptr;
        }

        const auto offset = header.code_offsets[index] - header.code_offsets[0];
        const auto code = state.analysis.baseline->executable_code;
        return code.data() + offset;
    }

    static TermResult return_impl(StackTop<BlueprintFieldType> stack, int64_t gas_left, ExecutionState<BlueprintFieldType>& state, evmc_status_code StatusCode) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id, stack.size(state.stack_space.bottom()) - 2, state.rw_trace.size(), false, stack[1]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id, stack.size(state.stack_space.bottom()) - 1, state.rw_trace.size(), false, stack[0]));
        const auto& offset = stack[0];
        const auto& size = stack[1];

        if (!check_memory(gas_left, state.memory, offset, size))
            return {EVMC_OUT_OF_GAS, gas_left};

        state.output_size = size.to_uint64();
        if (state.output_size != 0)
            state.output_offset = offset.to_uint64();
        return {StatusCode, gas_left};
    }
    static TermResult return_(StackTop<BlueprintFieldType> stack, int64_t gas_left, ExecutionState<BlueprintFieldType>& state) noexcept {
        return return_impl(stack, gas_left, state, EVMC_SUCCESS);
    }

    static TermResult revert(StackTop<BlueprintFieldType> stack, int64_t gas_left, ExecutionState<BlueprintFieldType>& state) noexcept {
        return return_impl(stack, gas_left, state, EVMC_REVERT);
    }

    static TermResult selfdestruct(StackTop<BlueprintFieldType> stack, int64_t gas_left, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        if (state.in_static_mode())
            return {EVMC_STATIC_MODE_VIOLATION, gas_left};

        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id, stack.size(state.stack_space.bottom()) - 1, state.rw_trace.size(), false, stack[0]));
        const auto beneficiary = stack[0].to_address();

        if (state.rev >= EVMC_BERLIN && state.host.access_account(beneficiary) == EVMC_ACCESS_COLD)
        {
            if ((gas_left -= instr::cold_account_access_cost) < 0)
                return {EVMC_OUT_OF_GAS, gas_left};
        }

        if (state.rev >= EVMC_TANGERINE_WHISTLE)
        {
            if (state.rev == EVMC_TANGERINE_WHISTLE || state.host.get_balance(state.msg->recipient))
            {
                // After TANGERINE_WHISTLE apply additional cost of
                // sending value to a non-existing account.
                if (!state.host.account_exists(beneficiary))
                {
                    if ((gas_left -= 25000) < 0)
                        return {EVMC_OUT_OF_GAS, gas_left};
                }
            }
        }

        if (state.host.selfdestruct(state.msg->recipient, beneficiary))
        {
            if (state.rev < EVMC_LONDON)
                state.gas_refund += 24000;
        }
        return {EVMC_SUCCESS, gas_left};
    }

    static Result sload(StackTop<BlueprintFieldType> stack, int64_t gas_left, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id, stack.size(state.stack_space.bottom()) - 1, state.rw_trace.size(), false, stack[0]));
        auto& x = stack.top();
        const auto key = x.to_uint256be();

        if (state.rev >= EVMC_BERLIN &&
            state.host.access_storage(state.msg->recipient, key) == EVMC_ACCESS_COLD)
        {
            // The warm storage access cost is already applied (from the cost table).
            // Here we need to apply additional cold storage access cost.
            constexpr auto additional_cold_sload_cost =
                instr::cold_sload_cost - instr::warm_storage_read_cost;
            if ((gas_left -= additional_cold_sload_cost) < 0)
                return {EVMC_OUT_OF_GAS, gas_left};
        }

        const auto value = nil::evm_assigner::zkevm_word<BlueprintFieldType>(state.host.get_storage(state.msg->recipient, key));
        state.rw_trace.push_back(storage_operation<BlueprintFieldType>(
                        state.call_id,
                        nil::evm_assigner::zkevm_word<BlueprintFieldType>(state.msg->recipient),// should be transaction_id), WHY???
                        x,
                        state.rw_trace.size(),
                        false,
                        value,
                        value
                    ));
        x = value;
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id, stack.size(state.stack_space.bottom()) - 1, state.rw_trace.size(), true, stack[0]));

        return {EVMC_SUCCESS, gas_left};
    }

    static Result sstore(StackTop<BlueprintFieldType> stack, int64_t gas_left, ExecutionState<BlueprintFieldType>& state) noexcept
    {
        if (state.in_static_mode())
            return {EVMC_STATIC_MODE_VIOLATION, gas_left};

        if (state.rev >= EVMC_ISTANBUL && gas_left <= 2300)
            return {EVMC_OUT_OF_GAS, gas_left};

        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id, stack.size(state.stack_space.bottom()) - 2, state.rw_trace.size(), false, stack[1]));
        state.rw_trace.push_back(stack_operation<BlueprintFieldType>(state.call_id, stack.size(state.stack_space.bottom()) - 1, state.rw_trace.size(), false, stack[0]));
        const auto key = stack.pop();
        const auto value = stack.pop();
        const auto key_uint64 = key.to_uint256be();
        const auto value_uint64 = value.to_uint256be();

        const auto gas_cost_cold =
            (state.rev >= EVMC_BERLIN &&
                state.host.access_storage(state.msg->recipient, key_uint64) == EVMC_ACCESS_COLD) ?
                instr::cold_sload_cost :
                0;
        state.rw_trace.push_back(storage_operation<BlueprintFieldType>(
                        state.call_id,//TODO should be transaction_id)
                        nil::evm_assigner::zkevm_word<BlueprintFieldType>(state.msg->recipient),
                        key,
                        state.rw_trace.size(),
                        true,
                        value,
                        state.host.get_storage(state.msg->recipient, key_uint64)
                    ));
        const auto status = state.host.set_storage(state.msg->recipient, key_uint64, value_uint64);

        const auto [gas_cost_warm, gas_refund] = sstore_costs[state.rev][status];
        const auto gas_cost = gas_cost_warm + gas_cost_cold;
        if ((gas_left -= gas_cost) < 0)
            return {EVMC_OUT_OF_GAS, gas_left};
        state.gas_refund += gas_refund;
        return {EVMC_SUCCESS, gas_left};
    }
}; // struct instructions
}  // namespace instr::core
}  // namespace evmone
