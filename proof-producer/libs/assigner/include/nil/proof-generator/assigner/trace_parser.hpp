#ifndef PROOF_GENERATOR_LIBS_ASSIGNER_TRACE_PARSER_HPP_
#define PROOF_GENERATOR_LIBS_ASSIGNER_TRACE_PARSER_HPP_

#include <stdexcept>
#include <utility>
#include <fstream>
#include <ios>
#include <optional>
#include <string>
#include <cstdint>
#include <format>

#include <boost/filesystem.hpp>
#include <boost/log/trivial.hpp>
#include <boost/filesystem.hpp>

#include <nil/blueprint/zkevm_bbf/types/zkevm_word.hpp>
#include <nil/blueprint/zkevm_bbf/types/rw_operation.hpp>
#include <nil/blueprint/zkevm_bbf/types/zkevm_state.hpp>
#include <nil/blueprint/zkevm_bbf/types/copy_event.hpp>
#include <nil/blueprint/assert.hpp>

#include <nil/proof-generator/assigner/trace.pb.h>
#include <nil/proof-generator/assigner/options.hpp>
#include "proto_hash.h"

namespace nil {
    namespace proof_producer {

        class trace_hash_mismatch : public std::logic_error {
        public:
            explicit trace_hash_mismatch(const std::string& path, const std::string& expectedHash, const std::string& readHash):
                std::logic_error(std::format("Trace '{}' hash mismatch: expected {}, got {}", path, expectedHash, readHash)) {}
        };

        class trace_io_error : public std::logic_error {
        public:
            explicit trace_io_error(const std::string& path):
                std::logic_error(std::format("Read '{}' trace io error", path)) {}
        };

        class trace_parse_error : public std::logic_error {
        public:
            explicit trace_parse_error(const std::string& path):
                std::logic_error(std::format("Parse '{}' trace error", path)) {}
        };

        class trace_index_mismatch : public std::logic_error {
        public:
            explicit trace_index_mismatch(const std::string& path, uint64_t expectedIndex, uint64_t readIndex):
                std::logic_error(std::format("Trace '{}' index mismatch: expected {}, got {}", path, expectedIndex, readIndex)) {}
        };



        const char BYTECODE_EXTENSION[] = ".bc";
        const char RW_EXTENSION[] = ".rw";
        const char ZKEVM_EXTENSION[] = ".zkevm";
        const char COPY_EXTENSION[] = ".copy";
        const char MPT_EXTENSION[] = ".mpt";
        const char EXP_EXTENSION[] = ".exp";
        const char KECCAK_EXTENSION[] = ".keccak";

        using TraceIndex = uint64_t; // value expected to be the same for all traces from the same set
        using TraceIndexOpt = std::optional<TraceIndex>;

        namespace {
            using exp_input = std::pair<blueprint::zkevm_word_type,blueprint::zkevm_word_type>; // base, exponent

            // Convert protobuf Uint256 to zkevm_word_type
            [[nodiscard]] blueprint::zkevm_word_type proto_uint256_to_zkevm_word(const executionproofs::Uint256& pb_uint) {
                blueprint::zkevm_word_type result = 0;
                for (size_t i = 0; i < pb_uint.word_parts_size() && i < 4; i++) {
                    result |= (static_cast<blueprint::zkevm_word_type>(pb_uint.word_parts(i)) << (i * 64));
                }
                return result;
            }

            boost::filesystem::path extend_base_path(boost::filesystem::path base,
                                                     const char* extension) {
                static const char BINARY_SERIALIZATION_EXTENSION[] = ".bin";
                return base.string() + extension + BINARY_SERIALIZATION_EXTENSION;
            }

            template<typename ProtoTraces>
            [[nodiscard]] ProtoTraces read_pb_traces_from_file(
                const boost::filesystem::path& filename,
                TraceIndexOpt index_base,
                const AssignerOptions& options
            ) {
                std::ifstream file(filename.c_str(), std::ios::in | std::ios::binary);
                if (!file.is_open()) {
                    throw trace_io_error(filename.string());
                }

                ProtoTraces pb_traces;
                if (!pb_traces.ParseFromIstream(&file)) {
                    throw trace_parse_error(filename.string());
                }

                if (pb_traces.proto_hash() != PROTO_HASH) {
                    throw trace_hash_mismatch(filename.string(), PROTO_HASH, pb_traces.proto_hash());

                }

                auto index = pb_traces.trace_idx();
                if (index_base.has_value() && index != *index_base) {
                    BOOST_LOG_TRIVIAL(warning) << "Trace index mismatch: expected " << *index_base << ", got " << index;
                    if (!options.ignore_index_mismatch) {
                        throw trace_index_mismatch(filename.string(), *index_base, index); // TODO: add filename
                    }
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
                    BOOST_LOG_TRIVIAL(error) << "Unknown copy operand type: " << static_cast<int>(pb_participant.location());
                    return std::nullopt;
                }

                const auto _type = it->second;
                blueprint::zkevm_word_type id{};
                switch (_type) {
                    case copy_operand_type::memory:
                    case copy_operand_type::calldata:
                    case copy_operand_type::returndata:
                    case copy_operand_type::log:
                        id = pb_participant.call_id();
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

        boost::filesystem::path get_bytecode_trace_path(const boost::filesystem::path& trace_base_path) {
            return extend_base_path(trace_base_path, BYTECODE_EXTENSION);
        }

        boost::filesystem::path get_rw_trace_path(const boost::filesystem::path& trace_base_path) {
            return extend_base_path(trace_base_path, RW_EXTENSION);
        }

        boost::filesystem::path get_zkevm_trace_path(const boost::filesystem::path& trace_base_path) {
            return extend_base_path(trace_base_path, ZKEVM_EXTENSION);
        }

        boost::filesystem::path get_copy_trace_path(const boost::filesystem::path& trace_base_path) {
            return extend_base_path(trace_base_path, COPY_EXTENSION);
        }

        boost::filesystem::path get_mpt_trace_path(const boost::filesystem::path& trace_base_path) {
            return extend_base_path(trace_base_path, MPT_EXTENSION);
        }

        boost::filesystem::path get_exp_trace_path(const boost::filesystem::path& trace_base_path) {
            return extend_base_path(trace_base_path, EXP_EXTENSION);
        }

        boost::filesystem::path get_keccak_trace_path(const boost::filesystem::path& trace_base_path) {
            return extend_base_path(trace_base_path, KECCAK_EXTENSION);
        }

        std::vector<std::uint8_t> string_to_bytes(const std::string& str) {
            std::vector<std::uint8_t> res(str.size());
            for (std::size_t i = 0; i < str.size(); i++) {
                res[i] = str[i];
            }
            return res;
        }


        template <typename TraceType>
        struct DeserializeResult {
            TraceType value;
            TraceIndex index;
        };

        template <typename T>
        using DeserializeResultOpt = std::optional<DeserializeResult<T>>;

        using BytecodeTraces = std::unordered_map<std::string, std::string>; // contract address -> bytecode
        using RWTraces = blueprint::bbf::rw_operations_vector;
        using ZKEVMTraces = std::vector<blueprint::bbf::zkevm_state>;
        using CopyEvents = std::vector<blueprint::bbf::copy_event>;
        using ExpTraces = std::vector<exp_input>;

        struct keccak_input {
            std::vector<uint8_t> buffer;
            blueprint::zkevm_word_type hash;
        };

        using KeccakTraces = std::vector<keccak_input>;

        [[nodiscard]] DeserializeResultOpt<BytecodeTraces> deserialize_bytecodes_from_file(
            const boost::filesystem::path& bytecode_trace_path,
            const AssignerOptions& opts,
            TraceIndexOpt base_index = {}
        ) {
            const auto pb_traces = read_pb_traces_from_file<executionproofs::BytecodeTraces>(bytecode_trace_path, base_index, opts);

            // Read executed op codes
            std::unordered_map<std::string, std::string> contract_bytecodes;
            const auto& bytecodes = pb_traces.contract_bytecodes();
            for (const auto& bytecode : bytecodes) {
                contract_bytecodes.emplace(bytecode.first, bytecode.second);
            }

            return DeserializeResult<BytecodeTraces>{
                std::move(contract_bytecodes),
                pb_traces.trace_idx()
            };
        }

        [[nodiscard]] DeserializeResultOpt<RWTraces> deserialize_rw_traces_from_file(
            const boost::filesystem::path& rw_traces_path,
            const AssignerOptions& opts,
            TraceIndexOpt base_index = {}
        ) {
            const auto pb_traces = read_pb_traces_from_file<executionproofs::RWTraces>(rw_traces_path, base_index, opts);

            blueprint::bbf::rw_operations_vector rw_traces;
            rw_traces.reserve(pb_traces.stack_ops_size() + pb_traces.memory_ops_size() + pb_traces.storage_ops_size() + 1); // +1 slot for start op

            // Convert stack operations
            for (const auto& pb_sop : pb_traces.stack_ops()) {
                rw_traces.push_back(blueprint::bbf::stack_rw_operation(
                    static_cast<uint64_t>(pb_sop.txn_id()),
                    static_cast<int32_t>(pb_sop.index()),
                    static_cast<uint64_t>(pb_sop.rw_idx()),
                    !pb_sop.is_read(),
                    proto_uint256_to_zkevm_word(pb_sop.value()))
                );
            }

            // Convert memory operations
            for (const auto& pb_mop : pb_traces.memory_ops()) {
                auto value = string_to_bytes(pb_mop.value());
                auto const op = blueprint::bbf::memory_rw_operation(
                    static_cast<uint64_t>(pb_mop.txn_id()),
                    blueprint::zkevm_word_type(static_cast<int>(pb_mop.index())),
                    static_cast<uint64_t>(pb_mop.rw_idx()),
                    !pb_mop.is_read(),
                    blueprint::zkevm_word_from_bytes(value)
                );
                rw_traces.push_back(std::move(op));
            }

            // Convert storage operations
            for (const auto& pb_sop : pb_traces.storage_ops()) {
                throw std::logic_error("not enough data");
                /* auto op = blueprint::bbf::storage_rw_operation(
                    static_cast<uint64_t>(pb_sop.txn_id()),
                    blueprint::zkevm_word_from_string(static_cast<std::string>(pb_sop.key())),
                    static_cast<uint64_t>(pb_sop.rw_idx()),
                    !pb_sop.is_read(),
                    proto_uint256_to_zkevm_word(pb_sop.value()),
                    proto_uint256_to_zkevm_word(pb_sop.prev_value()),
                    blueprint::zkevm_word_from_string(pb_sop.address().address_bytes())
                ); 
                //TODO root and initial_root?
                rw_traces.push_back(std::move(op)); */
            }

            std::sort(rw_traces.begin(), rw_traces.end(), std::less());

            BOOST_LOG_TRIVIAL(debug) << "number RW operations " << rw_traces.size() << ":\n"
                                     << "stack   " << pb_traces.stack_ops_size() << "\n"
                                     << "memory  " << pb_traces.memory_ops_size() << "\n"
                                     << "storage " << pb_traces.storage_ops_size() << "\n";

            return DeserializeResult<RWTraces>{
                std::move(rw_traces),
                pb_traces.trace_idx()
            };
        }

        [[nodiscard]] DeserializeResultOpt<ZKEVMTraces> deserialize_zkevm_state_traces_from_file(
            const boost::filesystem::path& zkevm_traces_path,
            const AssignerOptions& opts,
            TraceIndexOpt base_index = {}
        ) {
            const auto pb_traces = read_pb_traces_from_file<executionproofs::ZKEVMTraces>(zkevm_traces_path, base_index, opts);

            std::vector<blueprint::bbf::zkevm_state> zkevm_states;
            zkevm_states.reserve(pb_traces.zkevm_states_size());
            for (const auto& pb_state : pb_traces.zkevm_states()) {
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

                blueprint::bbf::basic_zkevm_state_part basic_state = {
                    .call_id = static_cast<uint64_t>(pb_state.call_id()),
                    .bytecode_hash = blueprint::zkevm_word_from_string(static_cast<std::string>(pb_state.bytecode_hash())),
                    .opcode = static_cast<uint64_t>(pb_state.opcode()),
                    .pc = static_cast<uint64_t>(pb_state.pc()),
                    .stack_size = static_cast<uint64_t>(pb_state.stack_size()),
                    .memory_size = static_cast<uint64_t>(pb_state.memory_size()),
                    .rw_counter = static_cast<uint64_t>(pb_state.rw_idx()),
                    .gas = static_cast<uint64_t>(pb_state.gas()),
                    .stack_slice = stack,
                };

                if (blueprint::bbf::opcode_to_string(blueprint::bbf::opcode_from_number(basic_state.opcode)).starts_with("PUSH")) {
                    zkevm_states.emplace_back(basic_state, proto_uint256_to_zkevm_word(pb_state.additional_input()));
                } else {
                    zkevm_states.emplace_back(basic_state, memory);
                }

                // do we need it?
                // zkevm_states.back().tx_finish = static_cast<bool>(pb_state.tx_finish());
                // zkevm_states.back().error_opcode = static_cast<uint64_t>(pb_state.error_opcode());
            }

            return DeserializeResult<ZKEVMTraces>{
                std::move(zkevm_states),
                pb_traces.trace_idx()
            };
        }

        [[nodiscard]] DeserializeResultOpt<CopyEvents> deserialize_copy_events_from_file(
            const boost::filesystem::path& copy_traces_file,
            const AssignerOptions& opts,
            TraceIndexOpt base_index = {}
        ) {
            const auto pb_traces = read_pb_traces_from_file<executionproofs::CopyTraces>(copy_traces_file, base_index, opts);

            namespace bbf = blueprint::bbf;

            std::vector<bbf::copy_event> copy_events;
            copy_events.reserve(pb_traces.copy_events_size());
            for (const auto& pb_event: pb_traces.copy_events()) {
                const auto source = copy_operand_from_proto(pb_event.from());
                const auto dest = copy_operand_from_proto(pb_event.to());
                if (!source || !dest) {
                    throw trace_parse_error(copy_traces_file.string());
                }

                auto [src_type, src_id] = *source;
                auto [dst_type, dst_id] = *dest;

                auto src_address = pb_event.from().mem_address();
                auto dst_address = pb_event.to().mem_address();

                auto rw_counter = pb_event.rw_idx();
                auto bytes = string_to_bytes(pb_event.data());
                auto length = bytes.size();

                bbf::copy_event event;
                using enum bbf::copy_operand_type;
                if (src_type == memory && dst_type == keccak) {
                    event = bbf::keccak_copy_event(size_t{src_id}, src_address, rw_counter, dst_id, bytes.size());
                } else if (src_type == reverted && dst_type == reverted) {
                    event = bbf::revert_copy_event(size_t{src_id}, size_t{dst_id}, rw_counter, length);
                } else if (src_type == memory && dst_type == returndata) {
                    event = bbf::return_copy_event(size_t{src_id}, src_address, rw_counter, length);
                } else if (src_type == returndata && dst_type == memory) {
                  throw std::logic_error("returndatacopy or end_call_copy?");
                } else if (src_type == calldata && dst_type == memory) {
                  event = bbf::calldatacopy_copy_event(size_t{src_id}, src_address, dst_address, rw_counter, length);
                } else if (src_type == memory && dst_type == calldata) {
                  event = bbf::call_copy_event(size_t{src_id}, size_t{dst_id}, src_address, length);
                } else {
                  throw std::logic_error("incorrect copy event");
                }

                for (auto b : bytes) event.push_byte(b);

                copy_events.push_back(std::move(event));
            }

            return DeserializeResult<CopyEvents>{
                std::move(copy_events),
                pb_traces.trace_idx()
            };
        }

        [[nodiscard]] DeserializeResultOpt<ExpTraces> deserialize_exp_traces_from_file(
            const boost::filesystem::path& exp_traces_path,
            const AssignerOptions& opts,
            TraceIndexOpt base_index = {}
        ) {
            const auto pb_traces = read_pb_traces_from_file<executionproofs::ExpTraces>(exp_traces_path, base_index, opts);

            std::vector<exp_input> exps;
            exps.reserve(pb_traces.exp_ops_size());
            for (const auto& pb_exp_op : pb_traces.exp_ops()) {
                exps.emplace_back(
                    proto_uint256_to_zkevm_word(pb_exp_op.base()),
                    proto_uint256_to_zkevm_word(pb_exp_op.exponent())
                );
            }

            return DeserializeResult<ExpTraces>{
                std::move(exps),
                pb_traces.trace_idx()
            };
        }

        [[nodiscard]] DeserializeResultOpt<KeccakTraces> deserialize_keccak_traces_from_file(
            const boost::filesystem::path& keccak_traces_path,
            const AssignerOptions& opts,
            TraceIndexOpt base_index = {}
        ) {
            const auto pb_traces = read_pb_traces_from_file<executionproofs::KeccakTraces>(keccak_traces_path, base_index, opts);

            KeccakTraces result;
            result.reserve(pb_traces.hashed_buffers_size());
            for (const auto& pb_hashed_buffer: pb_traces.hashed_buffers()) {
                result.push_back(keccak_input{
                    .buffer = string_to_bytes(pb_hashed_buffer.buffer()),
                    .hash =proto_uint256_to_zkevm_word(pb_hashed_buffer.keccak_hash())
                });
            }

            return DeserializeResult<KeccakTraces>{
                .value = std::move(result),
                .index = pb_traces.trace_idx()
            };
        }
    } // namespace proof_producer
} // namespace nil
#endif  // PROOF_GENERATOR_LIBS_ASSIGNER_TRACE_PARSER_HPP_
