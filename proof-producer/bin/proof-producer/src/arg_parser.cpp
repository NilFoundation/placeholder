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

#include <arg_parser.hpp>

#include <nil/proof-generator/arithmetization_params.hpp>

#include <iostream>
#include <fstream>
#include <string>
#include <type_traits>

#include <boost/algorithm/string.hpp>
#include <boost/program_options.hpp>
#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>

namespace nil {
    namespace proof_producer {
        namespace po = boost::program_options;

        namespace {
            template<typename T>
            po::typed_value<T>* make_defaulted_option(T& variable) {
                return po::value(&variable)->default_value(variable);
            }
        }

        std::optional<ProverOptions> parse_args(int argc, char* argv[]) {
            po::options_description options("Nil; Proof Generator Options");
            // Declare a group of options that will be
            // allowed only on command line
            po::options_description generic("CLI options");
            // clang-format off
            generic.add_options()
                ("help,h", "Produce help message")
                ("version,v", "Print version string")
                ("config,c", po::value<std::string>(), "Config file path");
            // clang-format on

            ProverOptions prover_options;

            // Declare a group of options that will be
            // allowed both on command line and in
            // config file
            po::options_description config(
                "Configuration",
                /*line_length=*/120,
                /*min_description_length=*/60
            );

            // clang-format off
            auto options_appender = config.add_options()
                ("stage", po::value(&prover_options.stage),
                 "Stage of the prover to run, one of (all, preprocess, prove, verify, generate-aggregated-challenge, generate-combined-Q, aggregated-FRI, consistency-checks). Defaults to 'all'.")
                ("log-level,l", make_defaulted_option(prover_options.log_level), "Log level (trace, debug, info, warning, error, fatal)") // TODO is does not work
                ("elliptic-curve-type,e", make_defaulted_option(prover_options.elliptic_curve_type), "Elliptic curve type (pallas, alt_bn128_254)")
                ("hash-type", po::value(&prover_options.hash_type_str), "Hash type (keccak, poseidon, sha256)");

            // clang-format on
            po::options_description cmdline_options("nil; Proof Producer");
            cmdline_options.add(generic).add(config);

            po::variables_map vm;
            std::optional<po::parsed_options> parsed_options;
            try {
                parsed_options = po::command_line_parser(argc, argv)
                    .options(cmdline_options)
                    .allow_unregistered()
                    .run();
                po::store(*parsed_options, vm);
            } catch (const po::validation_error& e) {
                std::cerr << e.what() << std::endl;
                std::cout << cmdline_options << std::endl;
                throw e;
            }

            if (vm.count("help")) {
                if (!vm.count("stage")) {
                    std::cout << cmdline_options << std::endl;
                    return std::nullopt;
                }
                prover_options.help_mode = true;
            }

            if (!vm.count("stage")) {
                prover_options.stage = "all";
            }

            if (vm.count("version")) {
#ifdef PROOF_GENERATOR_VERSION
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
                std::cout << TOSTRING(PROOF_GENERATOR_VERSION) << std::endl;
#undef STRINGIFY
#undef TOSTRING
#else
                std::cout << "undefined" << std::endl;
#endif
                return std::nullopt;
            }

            // Parse configuration file. Args from CLI will not be overwritten
            if (vm.count("config")) {
                std::ifstream ifs(vm["config"].as<std::string>().c_str());
                if (ifs) {
                    store(parse_config_file(ifs, config), vm);
                } else {
                    throw std::runtime_error("Cannot open config file: " + vm["config"].as<std::string>());
                }
            }

            // Calling notify(vm) after handling no-op cases prevent parser from alarming
            // about absence of required args
            try {
                notify(vm);
            } catch (const po::required_option& e) {
                std::cerr << e.what() << std::endl;
                std::cout << cmdline_options << std::endl;
                throw e;
            }

            boost::log::trivial::severity_level log_level;
            boost::log::trivial::from_string(prover_options.log_level.data(), prover_options.log_level.size(), log_level);
            boost::log::core::get()->set_filter(boost::log::trivial::severity >= log_level);

            prover_options.stage_args = po::collect_unrecognized(parsed_options->options, po::include_positional);

            return prover_options;
        }

// Here we have generators of read and write operators for options holding
// types. Don't forget to adjust help message when add new type - name mapping.
// Examples below.
#define GENERATE_WRITE_OPERATOR(TYPE_TO_STRING_LINES, VARIANT_TYPE)             \
    std::ostream& operator<<(std::ostream& strm, const VARIANT_TYPE& variant) { \
        strm << std::visit(                                                     \
            [&strm](auto&& arg) -> std::string {                                \
                using SelectedType = std::decay_t<decltype(arg)>;               \
                TYPE_TO_STRING_LINES                                            \
                strm.setstate(std::ios_base::failbit);                          \
                return "";                                                      \
            },                                                                  \
            variant                                                             \
        );                                                                      \
        return strm;                                                            \
    }
#define TYPE_TO_STRING(TYPE, NAME)                                   \
    if constexpr (std::is_same_v<SelectedType, type_identity<TYPE>>) \
        return NAME;

#define GENERATE_READ_OPERATOR(STRING_TO_TYPE_LINES, VARIANT_TYPE)        \
    std::istream& operator>>(std::istream& strm, VARIANT_TYPE& variant) { \
        std::string str;                                                  \
        strm >> str;                                                      \
        auto l = [&str, &strm]() -> VARIANT_TYPE {                        \
            STRING_TO_TYPE_LINES                                          \
            strm.setstate(std::ios_base::failbit);                        \
            return VARIANT_TYPE();                                        \
        };                                                                \
        variant = l();                                                    \
        return strm;                                                      \
    }
#define STRING_TO_TYPE(TYPE, NAME) \
    if (NAME == str)               \
        return type_identity<TYPE>{};

#define CURVE_TYPES                                                      \
    X(nil::crypto3::algebra::curves::alt_bn128<254>, "alt_bn128_254")    \
    X(nil::crypto3::algebra::curves::pallas, "pallas")
#define X(type, name) TYPE_TO_STRING(type, name)
        GENERATE_WRITE_OPERATOR(CURVE_TYPES, CurvesVariant)
#undef X
#define X(type, name) STRING_TO_TYPE(type, name)
        GENERATE_READ_OPERATOR(CURVE_TYPES, CurvesVariant)
#undef X

    } // namespace proof_producer
} // namespace nil
