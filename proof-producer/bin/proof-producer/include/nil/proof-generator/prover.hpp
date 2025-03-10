//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022-2023 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2024 Iosif (x-mass) <x-mass@nil.foundation>
// Copyright (c) 2024-2025 Daniil Kogtev <oclaw@nil.foundation>
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

#pragma once

#include <string>
#include <unordered_map>
#include <stdexcept>

namespace nil {
    namespace proof_producer {
        namespace detail {

            enum class ProverStage {
                ALL = 0,
                PRESET = 1,
                ASSIGNMENT = 2,
                PREPROCESS = 3,
                PROVE = 4,
                VERIFY = 5,
                GENERATE_AGGREGATED_CHALLENGE = 6,
                GENERATE_PARTIAL_PROOF = 7,
                FAST_GENERATE_PARTIAL_PROOF = 8,
                COMPUTE_COMBINED_Q = 9,
                GENERATE_AGGREGATED_FRI_PROOF = 10,
                GENERATE_CONSISTENCY_CHECKS_PROOF = 11,
                MERGE_PROOFS = 12,
                AGGREGATED_VERIFY = 13
            };

            ProverStage prover_stage_from_string(const std::string& stage) {
                static const std::unordered_map<std::string, ProverStage> stage_map = {
                    {"all", ProverStage::ALL},
                    {"preset", ProverStage::PRESET},
                    {"fill-assignment", ProverStage::ASSIGNMENT},
                    {"preprocess", ProverStage::PREPROCESS},
                    {"prove", ProverStage::PROVE},
                    {"verify", ProverStage::VERIFY},
                    {"generate-aggregated-challenge", ProverStage::GENERATE_AGGREGATED_CHALLENGE},
                    {"generate-partial-proof", ProverStage::GENERATE_PARTIAL_PROOF},
                    {"fast-generate-partial-proof", ProverStage::FAST_GENERATE_PARTIAL_PROOF},
                    {"compute-combined-Q", ProverStage::COMPUTE_COMBINED_Q},
                    {"merge-proofs", ProverStage::MERGE_PROOFS},
                    {"aggregated-FRI", ProverStage::GENERATE_AGGREGATED_FRI_PROOF},
                    {"consistency-checks", ProverStage::GENERATE_CONSISTENCY_CHECKS_PROOF},
                    {"aggregated-verify", ProverStage::AGGREGATED_VERIFY}
                };
                auto it = stage_map.find(stage);
                if (it == stage_map.end()) {
                    throw std::invalid_argument("Invalid stage: " + stage);
                }
                return it->second;
            }

        } // namespace detail
    } // namespace proof_producer
} // namespace nil
