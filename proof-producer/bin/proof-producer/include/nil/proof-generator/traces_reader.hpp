#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <unordered_map>

#include <nil/blueprint/zkevm/zkevm_word.hpp>

#include <nil/proof-generator/meta_utils.hpp>
#include <nil/proof-generator/traces.pb.h>


namespace nil {
    namespace proof_generator {

    struct StackOp {
        bool is_read;
        int idx;
        blueprint::zkevm_word_type value;
        uint64_t pc;
        uint32_t msg_id;
        uint64_t rw_idx;
    };

    struct MemoryOp {
        bool is_read;
        int idx;
        std::byte value;
        uint64_t pc;
        uint32_t msg_id;
        uint64_t rw_idx;
    };

    struct StorageOp {
        bool is_read;
        std::string key;  // hex string of hash
        blueprint::zkevm_word_type value;
        uint64_t pc;
        uint32_t msg_id;
        uint64_t rw_idx;
    };

    struct SlotChangeTrace {
        std::string key;          // hex string of hash
        std::string root_before;  // hex string of hash
        std::string root_after;   // hex string of hash
        blueprint::zkevm_word_type value_before;
        blueprint::zkevm_word_type value_after;
        std::vector<std::byte> proof;
    };

    struct ExecutionTraces {
        std::vector<StackOp> stack_ops;
        std::vector<MemoryOp> memory_ops;
        std::vector<StorageOp> storage_ops;
        std::vector<std::unordered_map<std::string, std::vector<SlotChangeTrace>>> slots_changes; // per message
        std::unordered_map<std::string, std::vector<std::byte>> contracts_bytecode;
    };

    [[nodiscard]] blueprint::zkevm_word_type proto_uint256_to_zkevm_word(const pb::Uint256& pb_uint) {
        blueprint::zkevm_word_type result = 0;
        for (size_t i = 0; i < pb_uint.word_parts_size() && i < 4; i++) {
            result |= (static_cast<blueprint::zkevm_word_type>(pb_uint.word_parts(i)) << (i * 64));
        }
        return result;
    }

    [[nodiscard]] std::optional<pb::ExecutionTraces> read_pb_traces_from_file(const boost::filesystem::path& filename) {
        if (!is_valid_path(filename.c_str()) || !can_read_from_file(filename.c_str())) {
            return std::nullopt;
        }

        auto file = open_file<std::ifstream>(filename.c_str(), std::ios::in | std::ios::binary);
        if (!file) {
            return std::nullopt;
        }

        pb::ExecutionTraces pb_traces;
        if (!pb_traces.ParseFromIstream(&*file)) {
            return std::nullopt;
        }

        return pb_traces;
    }

    [[nodiscard]] std::optional<ExecutionTraces> deserialize_traces_from_file(const boost::filesystem::path& filename) {
        const auto pb_traces = read_pb_traces_from_file(filename);
        if (!pb_traces) {
            return std::nullopt;
        }

        ExecutionTraces traces;

        // Convert stack operations
        traces.stack_ops.reserve(pb_traces->stack_ops_size());
        for (const auto& pb_sop : pb_traces->stack_ops()) {
            traces.stack_ops.push_back(StackOp{
                /*is_read=*/ pb_sop.is_read(),
                /*idx=*/ static_cast<int>(pb_sop.index()),
                /*value=*/ proto_uint256_to_zkevm_word(pb_sop.value()),
                /*pc=*/ pb_sop.pc(),
                /*msg_id=*/ static_cast<uint32_t>(pb_sop.msg_id()),
                /*rw_idx=*/ pb_sop.rw_idx()
            });
        }

        // Convert memory operations
        traces.memory_ops.reserve(pb_traces->memory_ops_size());
        for (const auto& pb_mop : pb_traces->memory_ops()) {
            traces.memory_ops.push_back(MemoryOp{
                /*is_read=*/ pb_mop.is_read(),
                /*idx=*/ static_cast<int>(pb_mop.index()),
                /*value=*/ static_cast<std::byte>(pb_mop.value()[0]),
                /*pc=*/ pb_mop.pc(),
                /*msg_id=*/ static_cast<uint32_t>(pb_mop.msg_id()),
                /*rw_idx=*/ pb_mop.rw_idx()
            });
        }

        // Convert storage operations
        traces.storage_ops.reserve(pb_traces->storage_ops_size());
        for (const auto& pb_sop : pb_traces->storage_ops()) {
            traces.storage_ops.push_back(StorageOp{
                /*is_read=*/ pb_sop.is_read(),
                /*key=*/ pb_sop.key(),
                /*value=*/ proto_uint256_to_zkevm_word(pb_sop.value()),
                /*pc=*/ pb_sop.pc(),
                /*msg_id=*/ static_cast<uint32_t>(pb_sop.msg_id()),
                /*rw_idx=*/ pb_sop.rw_idx()
            });
        }

        // Convert message traces (slots changes)
        traces.slots_changes.reserve(pb_traces->message_traces_size());
        for (const auto& pb_msg_trace : pb_traces->message_traces()) {
            std::unordered_map<std::string, std::vector<SlotChangeTrace>> addr_changes;

            for (const auto& [addr, pb_storage_traces] : pb_msg_trace.storage_traces_by_address()) {
                std::vector<SlotChangeTrace> slot_changes;
                slot_changes.reserve(pb_storage_traces.slots_changes_size());

                for (const auto& pb_slot : pb_storage_traces.slots_changes()) {
                    slot_changes.push_back(SlotChangeTrace{
                        /*key=*/ pb_slot.key(),
                        /*root_before=*/ pb_slot.root_before(),
                        /*root_after=*/ pb_slot.root_after(),
                        /*value_before=*/ proto_uint256_to_zkevm_word(pb_slot.value_before()),
                        /*value_after=*/ proto_uint256_to_zkevm_word(pb_slot.value_after()),
                        /*proof=*/ std::vector<std::byte>(
                            reinterpret_cast<const std::byte*>(pb_slot.ssz_proof().data()),
                            reinterpret_cast<const std::byte*>(pb_slot.ssz_proof().data() + pb_slot.ssz_proof().size())
                        )
                    });
                }
                addr_changes[addr] = std::move(slot_changes);
            }
            traces.slots_changes.push_back(std::move(addr_changes));
        }

        // Convert contract bytecodes
        for (const auto& [addr, bytecode] : pb_traces->contract_bytecodes()) {
            traces.contracts_bytecode[addr] = std::vector<std::byte>(
                reinterpret_cast<const std::byte*>(bytecode.data()),
                reinterpret_cast<const std::byte*>(bytecode.data() + bytecode.size())
            );
        }

        return traces;
    }

    } // namespace proof_generator
} // namespace nil
