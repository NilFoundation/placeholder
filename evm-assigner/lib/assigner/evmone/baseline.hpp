// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "eof.hpp"
#include "baseline_instruction_table.hpp"
#include "execution_state.hpp"
#include "instructions.hpp"

#include <evmc.h>
#include <utils.h>
#include <memory>
#include <string_view>
#include <vector>

#ifdef NDEBUG
#define release_inline gnu::always_inline, msvc::forceinline
#else
#define release_inline
#endif

#if defined(__GNUC__)
#define ASM_COMMENT(COMMENT) asm("# " #COMMENT)  // NOLINT(hicpp-no-assembler)
#else
#define ASM_COMMENT(COMMENT)
#endif

namespace evmone
{
using bytes_view = std::basic_string_view<uint8_t>;

template<typename BlueprintFieldType>
class ExecutionState;
class VM;

namespace baseline
{
class CodeAnalysis
{
public:
    using JumpdestMap = std::vector<bool>;

    bytes_view executable_code;  ///< Executable code section.
    JumpdestMap jumpdest_map;    ///< Map of valid jump destinations.
    EOF1Header eof_header;       ///< The EOF header.

private:
    /// Padded code for faster legacy code execution.
    /// If not nullptr the executable_code must point to it.
    std::unique_ptr<uint8_t[]> m_padded_code;

public:
    CodeAnalysis(std::unique_ptr<uint8_t[]> padded_code, size_t code_size, JumpdestMap map)
      : executable_code{padded_code.get(), code_size},
        jumpdest_map{std::move(map)},
        m_padded_code{std::move(padded_code)}
    {}

    CodeAnalysis(bytes_view code, EOF1Header header)
      : executable_code{code}, eof_header{std::move(header)}
    {}
};
static_assert(std::is_move_constructible_v<CodeAnalysis>);
static_assert(std::is_move_assignable_v<CodeAnalysis>);
static_assert(!std::is_copy_constructible_v<CodeAnalysis>);
static_assert(!std::is_copy_assignable_v<CodeAnalysis>);

CodeAnalysis analyze(evmc_revision rev, bytes_view code);

/// Analyze the code to build the bitmap of valid JUMPDEST locations.
EVMC_EXPORT CodeAnalysis analyze(evmc_revision rev, bytes_view code);

/// The execution position.
template <typename BlueprintFieldType>
struct Position
{
    code_iterator code_it;  ///< The position in the code.
    nil::evm_assigner::zkevm_word<BlueprintFieldType>* stack_top;     ///< The pointer to the stack top.
};

/// Checks instruction requirements before execution.
///
/// This checks:
/// - if the instruction is defined
/// - if stack height requirements are fulfilled (stack overflow, stack underflow)
/// - charges the instruction base gas cost and checks is there is any gas left.
///
/// @tparam         Op            Instruction opcode.
/// @param          cost_table    Table of base gas costs.
/// @param [in,out] gas_left      Gas left.
/// @param          stack_top     Pointer to the stack top item.
/// @param          stack_bottom  Pointer to the stack bottom.
///                               The stack height is stack_top - stack_bottom.
/// @return  Status code with information which check has failed
///          or EVMC_SUCCESS if everything is fine.
template <typename BlueprintFieldType>
inline evmc_status_code check_requirements(const CostTable& cost_table, int64_t& gas_left,
                                           const nil::evm_assigner::zkevm_word<BlueprintFieldType>* stack_top,
                                           const nil::evm_assigner::zkevm_word<BlueprintFieldType>* stack_bottom,
                                           Opcode op) noexcept
{
    assert(
        !instr::has_const_gas_cost(op) || instr::gas_costs[EVMC_FRONTIER][op] != instr::undefined);

    auto gas_cost = instr::gas_costs[EVMC_FRONTIER][op];  // Init assuming const cost.
    if (!instr::has_const_gas_cost(op))
    {
        gas_cost = cost_table[op];  // If not, load the cost from the table.

        // Negative cost marks an undefined instruction.
        // This check must be first to produce correct error code.
        if (gas_cost < 0)
            return EVMC_UNDEFINED_INSTRUCTION;
    }

    // Check stack requirements first. This is order is not required,
    // but it is nicer because complete gas check may need to inspect operands.
    if (instr::traits[op].stack_height_change > 0)
    {
        assert(instr::traits[op].stack_height_change == 1);
        if (stack_top == stack_bottom + StackSpace<BlueprintFieldType>::limit)
            return EVMC_STACK_OVERFLOW;
    }
    if (instr::traits[op].stack_height_required > 0)
    {
        // Check stack underflow using pointer comparison <= (better optimization).
        const auto min_offset = instr::traits[op].stack_height_required - 1;
        if (stack_top <= stack_bottom + min_offset)
            return EVMC_STACK_UNDERFLOW;
    }

    if ((gas_left -= gas_cost) < 0)
        return EVMC_OUT_OF_GAS;

    return EVMC_SUCCESS;
}

/// Helpers for invoking instruction implementations of different signatures.
/// @{
template <typename BlueprintFieldType>
[[release_inline]] inline code_iterator invoke(std::nullptr_t /*fn*/, Position<BlueprintFieldType> pos,
    int64_t& /*gas*/, ExecutionState<BlueprintFieldType>& /*state*/) noexcept
{
    return nullptr;
}

template <typename BlueprintFieldType>
[[release_inline]] inline code_iterator invoke(void (*instr_fn)(StackTop<BlueprintFieldType>) noexcept, Position<BlueprintFieldType> pos,
    int64_t& /*gas*/, ExecutionState<BlueprintFieldType>& /*state*/) noexcept
{
    instr_fn(pos.stack_top);
    return pos.code_it + 1;
}

template <typename BlueprintFieldType>
[[release_inline]] inline code_iterator invoke(
    Result (*instr_fn)(StackTop<BlueprintFieldType>, int64_t, ExecutionState<BlueprintFieldType>&) noexcept, Position<BlueprintFieldType> pos, int64_t& gas,
    ExecutionState<BlueprintFieldType>& state) noexcept
{
    const auto o = instr_fn(pos.stack_top, gas, state);
    gas = o.gas_left;
    if (o.status != EVMC_SUCCESS)
    {
        state.status = o.status;
        return nullptr;
    }
    return pos.code_it + 1;
}

template <typename BlueprintFieldType>
[[release_inline]] inline code_iterator invoke(void (*instr_fn)(StackTop<BlueprintFieldType>, ExecutionState<BlueprintFieldType>&) noexcept,
    Position<BlueprintFieldType> pos, int64_t& /*gas*/, ExecutionState<BlueprintFieldType>& state) noexcept
{
    instr_fn(pos.stack_top, state);
    return pos.code_it + 1;
}

template <typename BlueprintFieldType>
[[release_inline]] inline code_iterator invoke(
    code_iterator (*instr_fn)(StackTop<BlueprintFieldType>, ExecutionState<BlueprintFieldType>&, code_iterator) noexcept, Position<BlueprintFieldType> pos,
    int64_t& /*gas*/, ExecutionState<BlueprintFieldType>& state) noexcept
{
    return instr_fn(pos.stack_top, state, pos.code_it);
}

template <typename BlueprintFieldType>
[[release_inline]] inline code_iterator invoke(
    TermResult (*instr_fn)(StackTop<BlueprintFieldType>, int64_t, ExecutionState<BlueprintFieldType>&) noexcept, Position<BlueprintFieldType> pos, int64_t& gas,
    ExecutionState<BlueprintFieldType>& state) noexcept
{
    const auto result = instr_fn(pos.stack_top, gas, state);
    gas = result.gas_left;
    state.status = result.status;
    return nullptr;
}
/// A helper to invoke the instruction implementation of the given opcode Op.
template <typename BlueprintFieldType>
[[release_inline]] inline Position<BlueprintFieldType> invoke(const CostTable& cost_table, const nil::evm_assigner::zkevm_word<BlueprintFieldType>* stack_bottom,
    Position<BlueprintFieldType> pos, int64_t& gas, ExecutionState<BlueprintFieldType>& state, const uint8_t& op) noexcept
{
    if (const auto status = check_requirements<BlueprintFieldType>(cost_table, gas, pos.stack_top, stack_bottom, Opcode(op));
        status != EVMC_SUCCESS)
    {
        state.status = status;
        return {nullptr, pos.stack_top};
    }
    code_iterator new_pos = pos.code_it;
    switch (op)
    {
#undef ON_OPCODE_IDENTIFIER
#define ON_OPCODE_IDENTIFIER(OPCODE, IDENTIFIER)                         \
case OPCODE:                                                             \
    ASM_COMMENT(OPCODE);                                                 \
    new_pos = invoke(instr::core::IDENTIFIER, pos, gas, state);          \
    break;
    MAP_OPCODES
#undef ON_OPCODE_IDENTIFIER

    default:
        state.status = EVMC_UNDEFINED_INSTRUCTION;
        return {nullptr, pos.stack_top};;
    }
    const auto new_stack_top = pos.stack_top + instr::traits[op].stack_height_change;
    return Position<BlueprintFieldType>(new_pos, new_stack_top);
}
/// @}

template <bool TracingEnabled, typename BlueprintFieldType>
int64_t dispatch(const CostTable& cost_table, ExecutionState<BlueprintFieldType>& state, int64_t gas,
    const uint8_t* code) noexcept
{
    const auto stack_bottom = state.stack_space.bottom();

    // Code iterator and stack top pointer for interpreter loop.
    Position<BlueprintFieldType> position{code, stack_bottom};

    while (true)  // Guaranteed to terminate because padded code ends with STOP.
    {
        const auto op = *position.code_it;
        const auto next = invoke<BlueprintFieldType>(cost_table, stack_bottom, position, gas, state, op);
        if (next.code_it == nullptr)
        {
            return gas;
        } else {
            /*Update current position only when no error,
              this improves compiler optimization.*/
            position = next;
        }
    }
}

}  // namespace baseline
}  // namespace evmone
