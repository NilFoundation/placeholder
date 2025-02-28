//---------------------------------------------------------------------------//
// Copyright (c) 2025 Daniil Kogtev (oclaw) <oclaw@nil.foundation>
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

#include <boost/program_options.hpp>

#include <nil/proof-generator/preset/limits.hpp>
#include <nil/proof-generator/types/type_system.hpp>

namespace nil {
    namespace proof_producer {

        namespace po = boost::program_options;

        namespace {

            template<typename T>
            inline po::typed_value<T>* make_defaulted_option(T& variable) {
                return po::value(&variable)->default_value(variable);
            }

        }

        inline void register_circuits_limits_cli_args(CircuitsLimits& circuits_limits, po::options_description& cli_options) {
            cli_options.add_options()
            ("max-copy-rows", make_defaulted_option(circuits_limits.max_copy_rows), "Maximum number of copy table rows")
            ("max-rw-rows", make_defaulted_option(circuits_limits.max_rw_rows), "Maximum number of rw table rows")
            ("max-keccak-blocks", make_defaulted_option(circuits_limits.max_keccak_blocks), "Maximum keccak blocks")
            ("max-bytecode-rows", make_defaulted_option(circuits_limits.max_bytecode_rows), "Maximum number of bytecode table rows")
            ("max-total-rows", make_defaulted_option(circuits_limits.max_total_rows), "Maximum rows of assignemnt table")
            ("max-mpt-rows", make_defaulted_option(circuits_limits.max_mpt_rows), "Maximum number of MPT table rows")
            ("max-zkevm-rows", make_defaulted_option(circuits_limits.max_zkevm_rows), "Maximum number of zkevm table rows")
            ("max-exp-rows", make_defaulted_option(circuits_limits.max_exp_rows), "Maximum number of exponent table rows")
            ("max-exp-ops", make_defaulted_option(circuits_limits.max_exp_ops), "Maximum number of exponent operations")
            ("RLC-CHALLENGE", make_defaulted_option(circuits_limits.RLC_CHALLENGE), "RLC_CHALLENGE (7 by default)");
        }

        inline void register_placeholder_config_cli_args(PlaceholderConfig& config, po::options_description& cli_options) {
            cli_options.add_options()
                ("lambda-param", make_defaulted_option(config.lambda), "Lambda param (9)")
                ("grind-param", make_defaulted_option(config.grind), "Grind param (0)")
                ("expand-factor,x", make_defaulted_option(config.expand_factor), "Expand factor")
                ("max-quotient-chunks,q", make_defaulted_option(config.max_quotient_chunks), "Maximum quotient polynomial parts amount");
        }

    } // namespace proof_producer
} // namespace nil
