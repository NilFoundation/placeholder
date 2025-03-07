//---------------------------------------------------------------------------//
// Copyright (c) 2024 Iosif (x-mass) <x-mass@nil.foundation>
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

#include <optional>
#include <string>

#include <boost/filesystem/path.hpp>
#include <boost/log/trivial.hpp>

#include <nil/proof-generator/output_artifacts/output_artifacts.hpp>
#include <nil/proof-generator/arithmetization_params.hpp>
#include <nil/proof-generator/meta_utils.hpp>

namespace nil {
    namespace proof_producer {

        using CurvesVariant =
            typename tuple_to_variant<typename transform_tuple<CurveTypes, to_type_identity>::type>::type;

        struct ProverOptions {
            std::string stage = "all";
            std::string log_level = "info";
            CurvesVariant elliptic_curve_type = type_identity<nil::crypto3::algebra::curves::pallas>{};
            std::string hash_type_str = "keccak";


            bool help_mode{false};
            std::vector<std::string> stage_args; // stage arguments (not parsed on top level)
        };

        std::optional<ProverOptions> parse_args(int argc, char* argv[]);

    } // namespace proof_producer
} // namespace nil
