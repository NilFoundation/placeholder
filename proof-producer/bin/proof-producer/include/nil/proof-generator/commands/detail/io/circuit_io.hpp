#pragma once

#include <memory>

#include <boost/log/trivial.hpp>
#include <boost/filesystem.hpp>

#include <nil/proof-generator/resources.hpp>
#include <nil/proof-generator/types/type_system.hpp>
#include <nil/proof-generator/command_step.hpp>
#include <nil/proof-generator/marshalling_utils.hpp>
#include <nil/proof-generator/output_artifacts/circuit_writer.hpp>


namespace nil {
    namespace proof_generator {
 
        template <typename CurveType, typename HashType>
        struct CircuitIO {
            using Types = TypeSystem<CurveType, HashType>;
            using ConstraintSystem = Types::ConstraintSystem;
            using BlueprintField = Types::BlueprintField;
            using Endianness = Types::Endianness;
            using TTypeBase = Types::TTypeBase;

            struct Reader:
                public command_step,
                public resources::resource_provider<ConstraintSystem>
            {
                Reader(const boost::filesystem::path& circuit_file_path):
                    circuit_file_path_(circuit_file_path)
                {}

                CommandResult execute() override {
                    using resources::notify;

                    BOOST_LOG_TRIVIAL(info) << "read circuit from " << circuit_file_path_;

                    using ZkConstraintSystem = nil::crypto3::zk::snark::plonk_constraint_system<BlueprintField>;
                    using ConstraintMarshalling =
                        nil::crypto3::marshalling::types::plonk_constraint_system<TTypeBase, ZkConstraintSystem>;

                    auto marshalled_value = detail::decode_marshalling_from_file<ConstraintMarshalling>(circuit_file_path_);
                    if (!marshalled_value) {
                        return CommandResult::UnknownError("Failed to read circuit from {}", circuit_file_path_.string());
                    }
                    auto constraint_system = std::make_shared<ConstraintSystem>(
                        nil::crypto3::marshalling::types::make_plonk_constraint_system<Endianness, ZkConstraintSystem>(
                            *marshalled_value
                        )
                    );

                    notify<ConstraintSystem>(*this, constraint_system);

                    return CommandResult::Ok();
                }

            private:
                const boost::filesystem::path circuit_file_path_;
            };

            
            struct Writer: public command_step {

                Writer(resources::resource_provider<ConstraintSystem>& provider, const boost::filesystem::path& circuit_file_path): 
                    circuit_file_path_(circuit_file_path) 
                {
                    resources::subscribe_value(provider, constraint_system_);
                }

                CommandResult execute() override 
                {
                    using writer = circuit_writer<Endianness, BlueprintField>;

                    BOOST_LOG_TRIVIAL(info) << "Writing circuit to " << circuit_file_path_;
                    if (!constraint_system_) {
                        return CommandResult::UnknownError("No circuit is currently loaded");
                    }

                    std::ofstream out(circuit_file_path_, std::ios::binary | std::ios::out);
                    if (!out.is_open()) {
                        return CommandResult::UnknownError("Failed to open file {}", circuit_file_path_.string());
                    }

                    writer::write_binary_circuit(out, *constraint_system_, constraint_system_->public_input_sizes());
                    return CommandResult::Ok();
                }

            private:
                const boost::filesystem::path circuit_file_path_;
                std::shared_ptr<ConstraintSystem> constraint_system_;
            };
        };

    } // namespace proof_generator
} // namespace nil
