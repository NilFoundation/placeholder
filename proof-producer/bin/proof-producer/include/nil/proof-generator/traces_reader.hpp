#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <unordered_map>

#include <nil/blueprint/zkevm/zkevm_word.hpp>

#include <nil/proof-generator/meta_utils.hpp>
#include <nil/proof-generator/proof.pb.h>


namespace nil {
    namespace proof_generator {

    struct StackOp {
        bool is_read;
        int idx;
        blueprint::zkevm_word_type value;
        std::byte op_code;
    };

    struct MemoryOp {
        bool is_read;
        int idx;
        std::byte value;
        std::byte op_code;
    };

    struct ExecutionTraces {
        std::vector<StackOp> stack_ops;
        std::vector<MemoryOp> memory_ops;
        std::unordered_map<std::string, std::vector<std::vector<std::byte>>> storage_proofs;
    };

    // Convert protobuf Uint256 to zkevm_word_type
    [[nodiscard]] blueprint::zkevm_word_type proto_uint256_to_cpp(const executionproofs::Uint256& pb_uint) {
        blueprint::zkevm_word_type result = 0;
        for (size_t i = 0; i < pb_uint.word_parts_size() && i < 4; i++) {
            result |= (static_cast<blueprint::zkevm_word_type>(pb_uint.word_parts(i)) << (i * 64));
        }
        return result;
    }

    // Convert protobuf Proof to vector of bytes
    [[nodiscard]] std::vector<std::byte> proto_proof_to_cpp(const executionproofs::Proof& pb_proof) {
        const auto& data = pb_proof.proof_data();
        return std::vector<std::byte>(
            reinterpret_cast<const std::byte*>(data.data()),
            reinterpret_cast<const std::byte*>(data.data() + data.size())
        );
    }

    [[nodiscard]] std::optional<ExecutionTraces> deserialize_traces_from_file(const boost::filesystem::path& filename) {
        if (!is_valid_path(filename.c_str()) || !can_read_from_file(filename.c_str())) {
            return std::nullopt;
        }

        auto file = open_file<std::ifstream>(filename.c_str(), std::ios::in | std::ios::binary);
        if (!file) {
            return std::nullopt;
        }

        executionproofs::ExecutionTraces pb_traces;
        if (!pb_traces.ParseFromIstream(&*file)) {
            return std::nullopt;
        }

        ExecutionTraces traces;

        // Convert stack operations
        traces.stack_ops.reserve(pb_traces.stack_ops_size());
        for (const auto& pb_sop : pb_traces.stack_ops()) {
            traces.stack_ops.push_back(StackOp{
                /*is_read=*/ pb_sop.is_read(),
                /*idx=*/ static_cast<int>(pb_sop.index()),
                /*value=*/ proto_uint256_to_cpp(pb_sop.value()),
                /*op_code=*/ static_cast<std::byte>(pb_sop.op_code())
            });
        }

        // Convert memory operations
        traces.memory_ops.reserve(pb_traces.memory_ops_size());
        for (const auto& pb_mop : pb_traces.memory_ops()) {
            traces.memory_ops.push_back(MemoryOp{
                /*is_read=*/ pb_mop.is_read(),
                /*idx=*/ static_cast<int>(pb_mop.index()),
                /*value=*/ static_cast<std::byte>(pb_mop.value()[0]),
                /*op_code=*/ static_cast<std::byte>(pb_mop.op_code())
            });
        }

        // Convert storage proofs
        for (const auto& [addr_hex, pb_traces_addr] : pb_traces.storage_proofs_by_address()) {
            auto& proofs = traces.storage_proofs[addr_hex];
            proofs.reserve(pb_traces_addr.proof_list_size());

            for (const auto& pb_proof : pb_traces_addr.proof_list()) {
                proofs.push_back(proto_proof_to_cpp(pb_proof));
            }
        }

        return traces;
    }

    } // namespace proof_generator
} // namespace nil
