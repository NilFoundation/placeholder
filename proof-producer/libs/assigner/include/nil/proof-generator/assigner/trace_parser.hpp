#ifndef PROOF_GENERATOR_LIBS_ASSIGNER_TRACE_PARSER_HPP_
#define PROOF_GENERATOR_LIBS_ASSIGNER_TRACE_PARSER_HPP_

#include <nil/blueprint/zkevm/zkevm_word.hpp>
#include <nil/blueprint/zkevm_bbf/types/rw_operation.hpp>
#include <nil/blueprint/zkevm_bbf/types/zkevm_state.hpp>

#include <nil/proof-generator/assigner/trace.pb.h>


namespace nil {
    namespace proof_generator {

        struct RWOperations {
            std::vector<blueprint::bbf::rw_operation> stack_ops;
            std::vector<blueprint::bbf::rw_operation> memory_ops;
            std::vector<blueprint::bbf::rw_operation> storage_ops;
        };

        [[nodiscard]] std::optional<std::unordered_map<std::string, std::string>> deserialize_bytecodes_from_file(const boost::filesystem::path& filename);
        [[nodiscard]] std::optional<RWOperations> deserialize_rw_traces_from_file(const boost::filesystem::path& filename);
        [[nodiscard]] std::optional<std::vector<blueprint::bbf::zkevm_state>> deserialize_zkevm_state_traces_from_file(const boost::filesystem::path& filename);


        std::vector<std::uint8_t> string_to_bytes(const std::string& str);
    } // namespace proof_generator
} // namespace nil
#endif  // PROOF_GENERATOR_LIBS_ASSIGNER_TRACE_PARSER_HPP_
