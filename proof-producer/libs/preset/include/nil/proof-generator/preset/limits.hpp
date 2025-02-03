#pragma once

#include <cstdint>

namespace nil {
    namespace proof_producer {
        namespace limits {

            const std::size_t max_copy = 30000;
            const std::size_t max_rw_size = 60000;
            const std::size_t max_keccak_blocks = 500;
            const std::size_t max_bytecode_size = 20000;
            const std::size_t max_rows = 500000;
            const std::size_t max_mpt_size = 30;
            const std::size_t max_zkevm_rows = 25000;
            const std::size_t max_exp_rows = 25000;

            const std::size_t RLC_CHALLENGE = 7; // should be the same between all components
        } // limits

        struct CircuitsLimits {
            std::size_t max_copy;
            std::size_t max_rw_size;
            std::size_t max_keccak_blocks;
            std::size_t max_bytecode_size;
            std::size_t max_rows;
            std::size_t max_mpt_size;
            std::size_t max_zkevm_rows;
            std::size_t max_exp_rows;
            std::size_t RLC_CHALLENGE;

            CircuitsLimits():
                max_copy(limits::max_copy),
                max_rw_size(limits::max_rw_size),
                max_keccak_blocks(limits::max_keccak_blocks),
                max_bytecode_size(limits::max_bytecode_size),
                max_rows(limits::max_rows),
                max_mpt_size(limits::max_mpt_size),
                max_zkevm_rows(limits::max_zkevm_rows),
                max_exp_rows(limits::max_exp_rows),
                RLC_CHALLENGE(limits::RLC_CHALLENGE) {}
        };
    } // proof_producer
} // nil
