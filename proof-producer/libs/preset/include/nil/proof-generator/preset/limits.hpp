#pragma once

#include <cstdint>

namespace nil {
    namespace proof_producer {
        namespace limits {

            const std::size_t max_copy_rows = 30000;
            const std::size_t max_rw_rows = 60000;
            const std::size_t max_keccak_blocks = 25;
            const std::size_t max_bytecode_rows = 20000;
            const std::size_t max_total_rows = 150000;
            const std::size_t max_mpt_rows = 30;
            const std::size_t max_zkevm_rows = 25000;
            const std::size_t max_exp_rows = 25000;
            const std::size_t max_exp_ops = 50;
            const std::size_t max_call_commits = 500;

            const std::size_t RLC_CHALLENGE = 7; // should be the same between all components
        } // limits

        struct CircuitsLimits {
            std::size_t max_copy_rows;
            std::size_t max_rw_rows;
            std::size_t max_keccak_blocks;
            std::size_t max_bytecode_rows;
            std::size_t max_total_rows;
            std::size_t max_mpt_rows;
            std::size_t max_zkevm_rows;
            std::size_t max_exp_rows;
            std::size_t max_exp_ops;
            std::size_t max_call_commits;
            std::size_t RLC_CHALLENGE;

            CircuitsLimits():
                max_copy_rows(limits::max_copy_rows),
                max_rw_rows(limits::max_rw_rows),
                max_keccak_blocks(limits::max_keccak_blocks),
                max_bytecode_rows(limits::max_bytecode_rows),
                max_total_rows(limits::max_total_rows),
                max_mpt_rows(limits::max_mpt_rows),
                max_zkevm_rows(limits::max_zkevm_rows),
                max_exp_rows(limits::max_exp_rows),
                max_exp_ops(limits::max_exp_ops),
                max_call_commits(limits::max_call_commits),
                RLC_CHALLENGE(limits::RLC_CHALLENGE) {}
        };
    } // proof_producer
} // nil
