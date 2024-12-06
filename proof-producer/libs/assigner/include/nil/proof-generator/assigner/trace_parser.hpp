#ifndef PROOF_GENERATOR_LIBS_ASSIGNER_TRACE_PARSER_HPP_
#define PROOF_GENERATOR_LIBS_ASSIGNER_TRACE_PARSER_HPP_

#include <vector>
#include <string>
#include <cstdint>
#include <unordered_map>
#include <boost/filesystem.hpp>
#include <boost/log/trivial.hpp>
#include <boost/filesystem.hpp>

#include <nil/blueprint/zkevm/zkevm_word.hpp>
#include <nil/blueprint/zkevm_bbf/types/rw_operation.hpp>
#include <nil/blueprint/zkevm_bbf/types/zkevm_state.hpp>
#include <nil/blueprint/zkevm_bbf/types/copy_event.hpp>

#include <nil/proof-generator/assigner/trace.pb.h>

namespace nil {
    namespace proof_generator {

        struct RWOperations {
            std::vector<blueprint::bbf::rw_operation> stack_ops;
            std::vector<blueprint::bbf::rw_operation> memory_ops;
            std::vector<blueprint::bbf::rw_operation> storage_ops;
        };

        namespace {

            // Convert protobuf Uint256 to zkevm_word_type
            [[nodiscard]] blueprint::zkevm_word_type proto_uint256_to_zkevm_word(const executionproofs::Uint256& pb_uint) {
                blueprint::zkevm_word_integral_type result = 0;
                for (size_t i = 0; i < pb_uint.word_parts_size() && i < 4; i++) {
                    result |= (static_cast<blueprint::zkevm_word_integral_type>(pb_uint.word_parts(i)) << (i * 64));
                }
                return result;
            }

            [[nodiscard]] std::optional<executionproofs::ExecutionTraces> read_pb_traces_from_file(const boost::filesystem::path& filename) {
                std::ifstream file(filename.c_str(), std::ios::in | std::ios::binary);
                if (!file.is_open()) {
                    return std::nullopt;
                }
                if (!file) {
                    return std::nullopt;
                }

                executionproofs::ExecutionTraces pb_traces;
                if (!pb_traces.ParseFromIstream(&file)) {
                    return std::nullopt;
                }

                return pb_traces;
            }


            [[nodiscard]] std::optional<std::pair<
                blueprint::bbf::copy_operand_type,
                blueprint::zkevm_word_type>
            > copy_operand_from_proto(const ::executionproofs::CopyParticipant& pb_participant) noexcept {
                using ::executionproofs::CopyLocation;
                using blueprint::bbf::copy_operand_type;

                static const std::unordered_map<CopyLocation, copy_operand_type> mapping_ = {
                    {CopyLocation::MEMORY, copy_operand_type::memory},
                    {CopyLocation::BYTECODE, copy_operand_type::bytecode},
                    {CopyLocation::LOG, copy_operand_type::log},
                    {CopyLocation::KECCAK, copy_operand_type::keccak},
                    {CopyLocation::RETURNDATA, copy_operand_type::returndata},
                    {CopyLocation::CALLDATA, copy_operand_type::calldata}
                    // padding is not expected to be read from the trace file
                };

                const auto it = mapping_.find(pb_participant.location());
                if (it == mapping_.end()) {
                    BOOST_LOG_TRIVIAL(warning) << "Unknown copy operand type: " << static_cast<int>(pb_participant.location());
                    return std::nullopt;
                }

                const auto _type = it->second;
                blueprint::zkevm_word_type id{};
                switch (_type) {
                    case copy_operand_type::memory:
                    case copy_operand_type::calldata:
                    case copy_operand_type::returndata:
                    case copy_operand_type::log:
                        id.assign(pb_participant.call_id());
                        break;
                    case copy_operand_type::bytecode:
                        id = blueprint::zkevm_word_from_string(pb_participant.bytecode_hash());
                        break;
                    case copy_operand_type::keccak:
                        id = blueprint::zkevm_word_from_string(pb_participant.keccak_hash());
                        break;
                    default:
                        BOOST_LOG_TRIVIAL(warning) << "Unable to determine id for copy operand: " << static_cast<int>(_type);
                        return std::nullopt;
                }

                return std::make_pair(_type, id);
            }
        } // namespace

        std::vector<std::uint8_t> string_to_bytes(const std::string& str) {
            std::vector<std::uint8_t> res(str.size());
            for (std::size_t i = 0; i < str.size(); i++) {
                res[i] = str[i];
            }
            return res;
        }

        [[nodiscard]] std::optional<std::unordered_map<std::string, std::string>> deserialize_bytecodes_from_file(const boost::filesystem::path& filename) {
            const auto pb_traces = read_pb_traces_from_file(filename);
            if (!pb_traces) {
                return std::nullopt;
            }

            // Read executed op codes
            std::unordered_map<std::string, std::string> contract_bytecodes;
            const auto& bytecodes = pb_traces->contract_bytecodes();
            for (const auto& bytecode : bytecodes) {
                contract_bytecodes.emplace(bytecode.first, bytecode.second);
            }

            return contract_bytecodes;
        }

        [[nodiscard]] std::optional<RWOperations> deserialize_rw_traces_from_file(const boost::filesystem::path& filename) {
            const auto pb_traces = read_pb_traces_from_file(filename);
            if (!pb_traces) {
                return std::nullopt;
            }

            RWOperations rw_traces;

            // Convert stack operations
            rw_traces.stack_ops.reserve(pb_traces->stack_ops_size());
            for (const auto& pb_sop : pb_traces->stack_ops()) {
                rw_traces.stack_ops.push_back(blueprint::bbf::stack_rw_operation(
                    static_cast<uint64_t>(pb_sop.msg_id()),
                    static_cast<int32_t>(pb_sop.index()),
                    static_cast<uint64_t>(pb_sop.rw_idx()),
                    !pb_sop.is_read(),
                    proto_uint256_to_zkevm_word(pb_sop.value()))
                );
            }

            // Convert memory operations
            rw_traces.memory_ops.reserve(pb_traces->memory_ops_size());
            for (const auto& pb_mop : pb_traces->memory_ops()) {
                auto const value = string_to_bytes(pb_mop.value());
                auto const op = blueprint::bbf::memory_rw_operation(
                    static_cast<uint64_t>(pb_mop.msg_id()),
                    blueprint::zkevm_word_type(static_cast<int>(pb_mop.index())),
                    static_cast<uint64_t>(pb_mop.rw_idx()),
                    !pb_mop.is_read(),
                    blueprint::zkevm_word_from_bytes(value)
                );
                rw_traces.memory_ops.push_back(op);
            }

            // Convert storage operations
            rw_traces.storage_ops.reserve(pb_traces->storage_ops_size());
            for (const auto& pb_sop : pb_traces->storage_ops()) {
                const auto& op = blueprint::bbf::storage_rw_operation(
                    static_cast<uint64_t>(pb_sop.msg_id()),
                    blueprint::zkevm_word_from_string(static_cast<std::string>(pb_sop.key())),
                    static_cast<uint64_t>(pb_sop.rw_idx()),
                    !pb_sop.is_read(),
                    proto_uint256_to_zkevm_word(pb_sop.value()),
                    proto_uint256_to_zkevm_word(pb_sop.initial_value()),
                    blueprint::zkevm_word_from_string(pb_sop.address().address_bytes())
                );
                //TODO root and initial_root?
                rw_traces.storage_ops.push_back(std::move(op));
            }

            return rw_traces;
        }

        [[nodiscard]] std::optional<std::vector<blueprint::bbf::zkevm_state>> deserialize_zkevm_state_traces_from_file(const boost::filesystem::path& filename) {
            const auto pb_traces = read_pb_traces_from_file(filename);
            if (!pb_traces) {
                return std::nullopt;
            }

            std::vector<blueprint::bbf::zkevm_state> zkevm_states;
            zkevm_states.reserve(pb_traces->zkevm_states_size());
            for (const auto& pb_state : pb_traces->zkevm_states()) {
                std::vector<blueprint::zkevm_word_type> stack;
                stack.reserve(pb_state.stack_slice_size());
                for (const auto& pb_stack_val : pb_state.stack_slice()) {
                    stack.push_back(proto_uint256_to_zkevm_word(pb_stack_val));
                }
                std::map<std::size_t, std::uint8_t> memory;
                for (const auto& pb_memory_val : pb_state.memory_slice()) {
                    memory.emplace(pb_memory_val.first, pb_memory_val.second);
                }
                std::map<blueprint::zkevm_word_type, blueprint::zkevm_word_type> storage;
                for (const auto& pb_storage_entry : pb_state.storage_slice()) {
                    storage.emplace(proto_uint256_to_zkevm_word(pb_storage_entry.key()), proto_uint256_to_zkevm_word(pb_storage_entry.value()));
                }
                zkevm_states.emplace_back(stack, memory, storage);
                zkevm_states.back().call_id = static_cast<uint64_t>(pb_state.call_id());
                zkevm_states.back().pc = static_cast<uint64_t>(pb_state.pc());
                zkevm_states.back().gas = static_cast<uint64_t>(pb_state.gas());
                zkevm_states.back().rw_counter = static_cast<uint64_t>(pb_state.rw_idx());
                zkevm_states.back().bytecode_hash = blueprint::zkevm_word_from_string(static_cast<std::string>(pb_state.bytecode_hash()));
                zkevm_states.back().opcode = static_cast<uint64_t>(pb_state.opcode());
                zkevm_states.back().additional_input = proto_uint256_to_zkevm_word(pb_state.additional_input()),
                zkevm_states.back().stack_size = static_cast<uint64_t>(pb_state.stack_size());
                zkevm_states.back().memory_size = static_cast<uint64_t>(pb_state.memory_size());
                zkevm_states.back().tx_finish = static_cast<bool>(pb_state.tx_finish());
                zkevm_states.back().error_opcode = static_cast<uint64_t>(pb_state.error_opcode());
            }

            return zkevm_states;
        }

        [[nodiscard]] std::optional<std::vector<blueprint::bbf::copy_event>> deserialize_copy_events_from_file(const boost::filesystem::path& filename) {
            const auto pb_traces = read_pb_traces_from_file(filename);
            if (!pb_traces) {
                return std::nullopt;
            }

            namespace bbf = blueprint::bbf;

            std::vector<bbf::copy_event> copy_events;
            copy_events.reserve(pb_traces->copy_events_size());
            for (const auto& pb_event: pb_traces->copy_events()) {
                bbf::copy_event event;
                event.initial_rw_counter = pb_event.rw_idx();

                const auto source = copy_operand_from_proto(pb_event.from());
                if (!source) {
                    return std::nullopt;
                }
                event.source_type = source->first;
                event.source_id = source->second;
                event.src_address = pb_event.from().mem_address();

                const auto dest = copy_operand_from_proto(pb_event.to());
                if (!dest) {
                    return std::nullopt;
                }
                event.destination_type = dest->first;
                event.destination_id = dest->second;
                event.dst_address = pb_event.to().mem_address();

                event.bytes = std::move(string_to_bytes(pb_event.data()));
                event.length = event.bytes.size();

                copy_events.push_back(std::move(event));
            }

            return copy_events;
        }
    } // namespace proof_generator
} // namespace nil
#endif  // PROOF_GENERATOR_LIBS_ASSIGNER_TRACE_PARSER_HPP_
