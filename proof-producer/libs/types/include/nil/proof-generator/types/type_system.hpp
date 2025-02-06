//---------------------------------------------------------------------------//
// Copyright (c) 2025 Daniil Kogtev <oclaw@nil.foundation>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//---------------------------------------------------------------------------//

#ifndef PROOF_GENERATOR_ASSIGNER_TYPE_SYSTEM_HPP
#define PROOF_GENERATOR_ASSIGNER_TYPE_SYSTEM_HPP

#include <nil/marshalling/endianness.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/status_type.hpp>

#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/eval_storage.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/lpc.hpp>
#include <nil/crypto3/marshalling/zk/types/placeholder/common_data.hpp>
#include <nil/crypto3/marshalling/zk/types/placeholder/preprocessed_public_data.hpp>
#include <nil/crypto3/marshalling/zk/types/placeholder/proof.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/assignment_table.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/commitments/polynomial/lpc.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/placeholder_policy.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/profiling.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/proof.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/prover.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/verifier.hpp>
#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>

#include <nil/blueprint/transpiler/recursive_verifier_generator.hpp>
#include <nil/blueprint/transpiler/lpc_evm_verifier_gen.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>


namespace nil {
    namespace proof_producer {

        // TODO naming
        template <typename BlueprintField>
        struct PresetTypes {
            using ConstraintSystem = nil::blueprint::circuit<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintField>>;
            using AssignmentTable = nil::crypto3::zk::snark::plonk_assignment_table<BlueprintField>;
            using TableDescription = nil::crypto3::zk::snark::plonk_table_description<BlueprintField>;
        };

        // common type definitions needed for proof generation & verification steps
        template<typename CurveType, typename HashType>
        struct TypeSystem {
            using BlueprintField = typename CurveType::scalar_field_type;
            using LpcParams = nil::crypto3::zk::commitments::list_polynomial_commitment_params<HashType, HashType, 2>;
            using Lpc = nil::crypto3::zk::commitments::list_polynomial_commitment<BlueprintField, LpcParams>;
            using LpcScheme = typename nil::crypto3::zk::commitments::lpc_commitment_scheme<Lpc>;
            using polynomial_type = typename LpcScheme::polynomial_type;
            using CircuitParams = nil::crypto3::zk::snark::placeholder_circuit_params<BlueprintField>;
            using PlaceholderParams = nil::crypto3::zk::snark::placeholder_params<CircuitParams, LpcScheme>;
            using Proof = nil::crypto3::zk::snark::placeholder_proof<BlueprintField, PlaceholderParams>;
            using PublicPreprocessedData = typename nil::crypto3::zk::snark::
                placeholder_public_preprocessor<BlueprintField, PlaceholderParams>::preprocessed_data_type;
            using CommonData = typename PublicPreprocessedData::common_data_type;
            using PrivatePreprocessedData = typename nil::crypto3::zk::snark::
                placeholder_private_preprocessor<BlueprintField, PlaceholderParams>::preprocessed_data_type;
            using ConstraintSystem = typename PresetTypes<BlueprintField>::ConstraintSystem;
            using TableDescription = typename PresetTypes<BlueprintField>::TableDescription;
            using Endianness = nil::crypto3::marshalling::option::big_endian;
            using FriType = typename Lpc::fri_type;
            using FriParams = typename FriType::params_type;
            using Column = nil::crypto3::zk::snark::plonk_column<BlueprintField>;

            using AssignmentTable = typename PresetTypes<BlueprintField>::AssignmentTable;
            using AssignmentPublicTable = typename AssignmentTable::public_table_type;
            using AssignmentPublicInput = typename AssignmentPublicTable::public_input_container_type;
            using AssignmentPrivateTable = typename AssignmentTable::private_table_type;

            using TTypeBase = nil::crypto3::marshalling::field_type<Endianness>;

            using TableMarshalling = nil::crypto3::marshalling::types::plonk_assignment_table<TTypeBase, AssignmentTable>;
        };

        struct PlaceholderConfig {
            const std::size_t max_quotient_chunks;
            const std::size_t expand_factor;
            const std::size_t lambda;
            const std::size_t grind;
        };
    }
}

#endif // PROOF_GENERATOR_ASSIGNER_TYPE_SYSTEM_HPP
