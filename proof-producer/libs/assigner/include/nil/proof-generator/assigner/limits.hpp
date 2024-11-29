#pragma once

#include <cstdint>

namespace nil {
    namespace proof_generator {
        namespace limits {

            const std::size_t max_copy = 60500;
            const std::size_t max_rw_size = 60000;
            const std::size_t max_keccak_blocks = 500;
            const std::size_t max_bytecode_size = 20000;
            const std::size_t max_rows = 500000;
            const std::size_t max_mpt_size = 30;
            const std::size_t max_zkevm_rows = 10000;

        } // limits
    } // proof_generator
} // nil
