#ifndef PROOF_GENERATOR_LIBS_ASSIGNER_TRACE_PARSER_HPP_
#define PROOF_GENERATOR_LIBS_ASSIGNER_TRACE_PARSER_HPP_

#include <nil/blueprint/zkevm/zkevm_word.hpp>
#include <nil/blueprint/zkevm_bbf/types/rw_operation.hpp>

#include <nil/proof-generator/assigner/trace.pb.h>


namespace nil {
    namespace proof_generator {

        struct StackOp {
            bool is_read;
            int32_t idx;
            blueprint::zkevm_word_type value;
            uint64_t pc;
            uint64_t msg_id;
            uint64_t raw_idx;
        };

        struct MemoryOp {
            bool is_read;
            int32_t index;
            std::string value;
            uint64_t pc;
            uint64_t msg_id;
            uint64_t rw_idx;
        };

        struct StorageOp {
            bool is_read;
            std::string key;
            blueprint::zkevm_word_type value;
            uint64_t pc;
            uint64_t msg_id;
            uint64_t rw_idx;
        };

        struct SlotChangeTrace {
            std::string key;
            std::string root_before;
            std::string root_after;
            blueprint::zkevm_word_type value_before;
            blueprint::zkevm_word_type value_after;
            std::string ssz_proof;
        };

        struct MessageTraces {
            std::unordered_map<std::string, SlotChangeTrace> storage_traces_by_address;
        };

        struct RWOperations {
            std::vector<blueprint::bbf::rw_operation> stack_ops;
            std::vector<blueprint::bbf::rw_operation> memory_ops;
            std::vector<blueprint::bbf::rw_operation> storage_ops;
        };

        [[nodiscard]] std::optional<std::unordered_map<std::string, std::string>> deserialize_bytecodes_from_file(const boost::filesystem::path& filename);
        [[nodiscard]] std::optional<RWOperations> deserialize_rw_traces_from_file(const boost::filesystem::path& filename);


        std::vector<std::uint8_t> string_to_bytes(const std::string& str);
    } // namespace proof_generator
} // namespace nil
#endif  // PROOF_GENERATOR_LIBS_ASSIGNER_TRACE_PARSER_HPP_
