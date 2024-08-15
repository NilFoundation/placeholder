//---------------------------------------------------------------------------//
// Copyright (c) Nil Foundation and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.
//---------------------------------------------------------------------------//

#ifndef EVM_ASSIGNER_LIB_ASSIGNER_INCLUDE_ASSIGNER_HPP_
#define EVM_ASSIGNER_LIB_ASSIGNER_INCLUDE_ASSIGNER_HPP_

#include <evmc.hpp>

#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/trivial.hpp>

#include <unordered_map>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

#include <bytecode.hpp>
#include <baseline.hpp>
#include <execution_state.hpp>
#include <rw.hpp>

namespace nil {
    namespace evm_assigner {

        enum zkevm_circuit : uint8_t {
            ALL = 0xFF,
            BYTECODE = 0x1,
            RW = 0x2
        };

        static const std::map<std::string, zkevm_circuit> zkevm_circuits_map = {
            {"", zkevm_circuit::ALL},
            {"bytecode", zkevm_circuit::BYTECODE},
            {"rw", zkevm_circuit::RW}
        };

        template<typename BlueprintFieldType>
        struct assigner {

            using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;

            constexpr static size_t BYTECODE_TABLE_INDEX = 0;
            constexpr static size_t RW_TABLE_INDEX = 1;

            assigner(std::unordered_map<uint8_t, nil::blueprint::assignment<ArithmetizationType>> &assignments):  m_assignments(assignments) {}

            // TODO error handling
            void handle_bytecode(size_t original_code_size, const uint8_t* code) {
                auto it = m_assignments.find(BYTECODE_TABLE_INDEX);
                if (it == m_assignments.end()) {
                    return;
                }
                return process_bytecode_input<BlueprintFieldType>(
                    original_code_size, code, it->second);
            }

            // TODO error handling
            void handle_rw(std::vector<rw_operation<BlueprintFieldType>>& rw_trace) {
                auto it = m_assignments.find(RW_TABLE_INDEX);
                if (it == m_assignments.end()) {
                    return;
                }
                return process_rw_operations<BlueprintFieldType>(
                    rw_trace, it->second);
            }

            std::unordered_map<uint8_t, nil::blueprint::assignment<ArithmetizationType>> &m_assignments;
        };

        template<typename BlueprintFieldType>
        static evmc::Result evaluate(const evmc_host_interface* host, evmc_host_context* ctx,
                                evmc_revision rev, const evmc_message* msg, const uint8_t* code_ptr, size_t code_size,
                                std::shared_ptr<nil::evm_assigner::assigner<BlueprintFieldType>> assigner, const std::string& target_circuit = "") {
            if(zkevm_circuits_map.find(target_circuit) == zkevm_circuits_map.end()) {
                std::cerr << "Unknown target circuit " << target_circuit << "\n";
                return evmc::Result{EVMC_FAILURE, msg->gas};
            }
            const auto zkevm_target_circuit = zkevm_circuits_map.find(target_circuit)->second;

            const evmone::bytes_view container{code_ptr, code_size};
            const auto code_analysis = evmone::baseline::analyze(rev, container);
            const auto data = code_analysis.eof_header.get_data(container);
            evmone::ExecutionState<BlueprintFieldType> state(*msg, rev, *host, ctx, container, data, 0, assigner);

            state.analysis.baseline = &code_analysis;  // Assign code analysis for instruction implementations.
            const auto code = code_analysis.executable_code;

            // fill assignments for bytecode circuit
            if (zkevm_target_circuit & zkevm_circuit::BYTECODE) {
                assigner->handle_bytecode(state.original_code.size(), code.data());
            }

            int64_t gas = msg->gas;

            const auto& cost_table = evmone::baseline::get_baseline_cost_table(state.rev, code_analysis.eof_header.version);

            BOOST_LOG_TRIVIAL(debug) << "Run evaluate\n";

            gas = evmone::baseline::dispatch<false>(cost_table, state, msg->gas, code.data());

            BOOST_LOG_TRIVIAL(debug) << "Evaluate result = " << state.status << "\n";

            // fill assignments for read/write circuit
            if (zkevm_target_circuit & zkevm_circuit::RW) {
                assigner->handle_rw(state.rw_trace);
            }

            const auto gas_left = (state.status == EVMC_SUCCESS || state.status == EVMC_REVERT) ? gas : 0;
            const auto gas_refund = (state.status == EVMC_SUCCESS) ? state.gas_refund : 0;

            assert(state.output_size != 0 || state.output_offset == 0);
            const auto evmc_result = evmc::make_result(state.status, gas_left, gas_refund,
                state.output_size != 0 ? &state.memory[state.output_offset] : nullptr, state.output_size);
            return evmc::Result{evmc_result};
        }

    }     // namespace evm_assigner
}    // namespace nil

#endif    // EVM_ASSIGNER_LIB_ASSIGNER_INCLUDE_ASSIGNER_HPP_
