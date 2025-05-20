//---------------------------------------------------------------------------//
// Copyright (c) 2025 Dmitrii Tabalin <dtabalin@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//
#define BOOST_TEST_MODULE plonk_keccak_round_benchmark

#include <array>
#include <cstdlib>
#include <ctime>
#include <random>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <fstream>

#include <boost/test/unit_test.hpp>

#include <nil/blueprint/bbf/circuit_builder.hpp>
#include <nil/blueprint/bbf/components/hashes/keccak/keccak_round_bench.hpp>
#include <nil/blueprint/bbf/components/hashes/keccak/keccak_permute_wide.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/prover.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/verifier.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>

using namespace nil::crypto3;
using namespace nil::blueprint;
using namespace nil::blueprint::bbf;

template<typename Duration>
std::string format_time(const Duration& duration) {
    std::stringstream ss;
    ss << std::fixed;
    auto nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(duration).count();

    if (nanoseconds < 1000) {
        ss << std::setprecision(0) << nanoseconds << " ns";
    } else if (nanoseconds < 1000000) {
        ss << std::setprecision(3) << (nanoseconds / 1000.0) << " μs";
    } else if (nanoseconds < 1000000000) {
        ss << std::setprecision(3) << (nanoseconds / 1000000.0) << " ms";
    } else {
        double seconds = nanoseconds / 1000000000.0;
        if (seconds < 60) {
            ss << std::setprecision(3) << seconds << " s";
        } else {
            int minutes = static_cast<int>(seconds) / 60;
            seconds -= minutes * 60;
            ss << minutes << "m " << std::setprecision(3) << seconds << "s";
        }
    }

    return ss.str();
}

// For non-void return types
template<typename Func, typename... Args>
auto measure_execution_time(Func func, Args&&... args)
    -> std::enable_if_t<!std::is_void_v<std::invoke_result_t<Func, Args...>>,
                        std::pair<std::invoke_result_t<Func, Args...>, std::chrono::high_resolution_clock::duration>> {
    auto start = std::chrono::high_resolution_clock::now();
    auto result = func(std::forward<Args>(args)...);
    auto end = std::chrono::high_resolution_clock::now();
    return std::make_pair(std::move(result), end - start);
}

// For void return types
template<typename Func, typename... Args>
auto measure_execution_time(Func func, Args&&... args)
    -> std::enable_if_t<std::is_void_v<std::invoke_result_t<Func, Args...>>,
                        std::chrono::high_resolution_clock::duration> {
    auto start = std::chrono::high_resolution_clock::now();
    func(std::forward<Args>(args)...);
    auto end = std::chrono::high_resolution_clock::now();
    return end - start;
}

template<typename BlueprintFieldType>
typename BlueprintFieldType::value_type to_sparse(typename BlueprintFieldType::value_type value) {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;
    integral_type value_integral = value.to_integral();
    integral_type result_integral = 0;
    integral_type power = 1;
    for (int i = 0; i < 64; ++i) {
        integral_type bit = value_integral & 1;
        result_integral = result_integral + bit * power;
        value_integral = value_integral >> 1;
        power = power << 3;
    }
    return value_type(result_integral);
}

template <typename BlueprintFieldType>
auto generate_proof(
    const nil::blueprint::circuit<zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
    const zk::snark::plonk_assignment_table<BlueprintFieldType> &assignment,
    const zk::snark::plonk_table_description<BlueprintFieldType> &desc
) {
    std::size_t Lambda = 9;

    typedef nil::crypto3::zk::snark::placeholder_circuit_params<BlueprintFieldType> circuit_params;
    using transcript_hash_type = nil::crypto3::hashes::keccak_1600<256>;
    using merkle_hash_type = nil::crypto3::hashes::keccak_1600<256>;
    using transcript_type = typename nil::crypto3::zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;
    using lpc_params_type = nil::crypto3::zk::commitments::list_polynomial_commitment_params<
        merkle_hash_type,
        transcript_hash_type,
        2 //m
    >;

    using lpc_type = nil::crypto3::zk::commitments::list_polynomial_commitment<BlueprintFieldType, lpc_params_type>;
    using lpc_scheme_type = typename nil::crypto3::zk::commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    typename lpc_type::fri_type::params_type fri_params(1, std::ceil(log2(assignment.rows_amount())), Lambda, 2);
    lpc_scheme_type lpc_scheme(fri_params);

    //std::cout << "Public preprocessor" << std::endl;
    // measure public preprocessor time separately, in order to subtract it from total time later
    auto public_preprocessor_start = std::chrono::high_resolution_clock::now();
    typename nil::crypto3::zk::snark::placeholder_public_preprocessor<BlueprintFieldType, lpc_placeholder_params_type>::preprocessed_data_type
            lpc_preprocessed_public_data = nil::crypto3::zk::snark::placeholder_public_preprocessor<BlueprintFieldType, lpc_placeholder_params_type>::process(
            bp, assignment.public_table(), desc, lpc_scheme, 10);
    auto public_preprocessor_end = std::chrono::high_resolution_clock::now();
    //std::cout << "Private preprocessor" << std::endl;
    auto proof_start = std::chrono::high_resolution_clock::now();
    typename nil::crypto3::zk::snark::placeholder_private_preprocessor<BlueprintFieldType, lpc_placeholder_params_type>::preprocessed_data_type
            lpc_preprocessed_private_data = nil::crypto3::zk::snark::placeholder_private_preprocessor<BlueprintFieldType, lpc_placeholder_params_type>::process(
            bp, assignment.private_table(), desc);

    //std::cout << "Prover" << std::endl;
    auto lpc_proof = nil::crypto3::zk::snark::placeholder_prover<BlueprintFieldType, lpc_placeholder_params_type>::process(
            lpc_preprocessed_public_data, std::move(lpc_preprocessed_private_data), desc, bp,
            lpc_scheme);
    auto proof_end = std::chrono::high_resolution_clock::now();

    // We must not use the same instance of lpc_scheme.
    lpc_scheme_type verifier_lpc_scheme(fri_params);

    //std::cout << "Verifier" << std::endl;
    //bool verifier_res = nil::crypto3::zk::snark::placeholder_verifier<BlueprintFieldType, lpc_placeholder_params_type>::process(
    //        *lpc_preprocessed_public_data.common_data, lpc_proof, desc, bp, verifier_lpc_scheme);
    return proof_end - proof_start;
}

template<typename BlueprintFieldType>
auto benchmark_keccak_round(const std::size_t expansion_factor, const std::size_t blocks) {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;
    using input_type = typename keccak_round_bench<BlueprintFieldType, GenerationStage::ASSIGNMENT>::input_type;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;
    std::vector<std::array<value_type, 25>> inner_states;
    std::vector<std::array<value_type, 17>> padded_message_chunks;
    for (std::size_t lane = 0; lane < expansion_factor; lane++) {
        std::array<value_type, 25> inner_state;
        std::array<value_type, 17> padded_message_chunk;
        integral_type mask = (integral_type(1) << 64) - 1;
        for (int i = 0; i < 25; ++i) {
            auto random_value = integral_type(dis(gen)) & mask;
            inner_state[i] = to_sparse<BlueprintFieldType>(value_type(random_value));
        }
        for (int i = 0; i < 17; ++i) {
            auto random_value = integral_type(dis(gen)) & mask;
            padded_message_chunk[i] = to_sparse<BlueprintFieldType>(value_type(random_value));
        }
        inner_states.push_back(inner_state);
        padded_message_chunks.push_back(padded_message_chunk);
    }
    auto B = bbf::circuit_builder<
        BlueprintFieldType,
        keccak_round_bench,
        std::size_t, std::size_t
    >(expansion_factor, blocks);
    auto b_assign = [&B](auto& inner_states, auto& padded_message_chunks) {
        return B.assign(
            input_type{inner_states, padded_message_chunks}
        );
    };
    auto [result, assgnment_time] = measure_execution_time(b_assign, inner_states, padded_message_chunks);
    auto [at, A, desc] = result;
    std::cout << "constants amount = " << desc.constant_columns << std::endl;
    // BOOST_TEST(B.is_satisfied(at), "constraints are not satisfied");
    auto proof_time = generate_proof<BlueprintFieldType>(B.get_circuit(), at, desc);
    return std::make_tuple(assgnment_time, proof_time);
}

template<typename BlueprintFieldType>
auto benchmark_keccak_permute_wide(const std::size_t instances, const std::size_t state_variant = 0) {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;
    
    // Generate array of inner states based on number of instances to test
    std::vector<std::array<value_type, 25>> inner_states;
    integral_type mask = (integral_type(1) << 64) - 1;
    
    for (std::size_t i = 0; i < instances; i++) {
        std::array<value_type, 25> inner_state;
        for (int j = 0; j < 25; ++j) {
            auto random_value = integral_type(dis(gen)) & mask;
            inner_state[j] = to_sparse<BlueprintFieldType>(value_type(random_value));
        }
        inner_states.push_back(inner_state);
    }

    // For now we only have one version of the keccak_permute_wide implementation
    // but we keep the state_variant parameter for future extensions
    (void)state_variant;

    std::chrono::high_resolution_clock::duration total_assgnment_time = std::chrono::high_resolution_clock::duration::zero();
    std::chrono::high_resolution_clock::duration total_proof_time = std::chrono::high_resolution_clock::duration::zero();

    for (std::size_t i = 0; i < instances; i++) {
        auto B = bbf::circuit_builder<
            BlueprintFieldType,
            keccak_permute_wide
        >();
        
        auto b_assign = [&B](const auto& state) {
            return B.assign(
                typename keccak_permute_wide<BlueprintFieldType, GenerationStage::ASSIGNMENT>::input_type{state}
            );
        };
        
        auto [result, assgnment_time] = measure_execution_time(b_assign, inner_states[i]);
        auto [at, A, desc] = result;

        if (i == 0) {
            std::cout << "constants amount = " << desc.constant_columns << std::endl;
        }

        auto proof_time = generate_proof<BlueprintFieldType>(B.get_circuit(), at, desc);

        total_assgnment_time += assgnment_time;
        total_proof_time += proof_time;

        std::cout << "Instance " << (i+1) << "/" << instances << " completed" << std::endl;
    }

    // Calculate averages
    auto avg_assignment_time = total_assgnment_time / instances;
    auto avg_proof_time = total_proof_time / instances;

    std::cout << "Average assignment time: " << format_time(avg_assignment_time) << std::endl;
    std::cout << "Average proof time: " << format_time(avg_proof_time) << std::endl;

    return std::make_tuple(avg_assignment_time, avg_proof_time);
}

void run_keccak_round_benchmarks(bool quick_mode = false, const std::string& output_file = "keccak_round_benchmarks.csv") {
    using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;

    // Open output file
    std::ofstream file_out(output_file);
    if (!file_out.is_open()) {
        std::cerr << "Failed to open output file: " << output_file << std::endl;
        return;
    }

    // Write header to both console and file
    std::cout << "expansion_factor,blocks,assignment_time,proof_time" << std::endl;
    file_out << "expansion_factor,blocks,assignment_time,proof_time" << std::endl;

    std::vector<size_t> expansion_factors;
    std::vector<size_t> base_block_counts = {32, 64, 128, 256, 512, 1024};

    // Define the sweep ranges
    if (quick_mode) {
        // Quick mode for testing - just a few small values
        expansion_factors = {1, 2};
    } else {
        // Full benchmark - powers of 2
        for (size_t e = 1; e <= 128; e *= 2) {
            expansion_factors.push_back(e);
        }
    }

    // Run benchmarks for each combination
    for (size_t expansion : expansion_factors) {
        // For each expansion factor, determine the max block count
        // Use 512 blocks for expansion factor 1, and double for each higher expansion factor
        size_t max_blocks = quick_mode ? 32 : 512 * expansion;
        size_t min_blocks = 32 * expansion;

        for (size_t blocks : base_block_counts) {
            // Skip if this block count exceeds the cap for this expansion factor
            if (blocks > max_blocks || blocks < min_blocks) {
                continue;
            }

            std::cout << "Running benchmark with expansion=" << expansion
                      << ", blocks=" << blocks << "..." << std::endl;

            auto [assignment_time, proof_time] = benchmark_keccak_round<field_type>(expansion, blocks);

            // Format benchmark result
            std::string result =
                std::to_string(expansion) + "," +
                std::to_string(blocks) + "," +
                std::to_string(std::chrono::duration_cast<std::chrono::microseconds>(assignment_time).count()) + "," +
                std::to_string(std::chrono::duration_cast<std::chrono::microseconds>(proof_time).count());

            // Output to both console and file
            std::cout << result << std::endl;
            file_out << result << std::endl;

            // Flush file buffer to ensure data is written even if program crashes
            file_out.flush();
        }
    }

    file_out.close();
    std::cout << "Benchmark results saved to " << output_file << std::endl;
}

void run_keccak_permute_wide_benchmarks(bool quick_mode = false, const std::string& output_file = "keccak_permute_wide_benchmarks.csv") {
    using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;

    // Open output file
    std::ofstream file_out(output_file);
    if (!file_out.is_open()) {
        std::cerr << "Failed to open output file: " << output_file << std::endl;
        return;
    }

    // Write header to both console and file
    std::cout << "instances,state_variant,assignment_time,proof_time" << std::endl;
    file_out << "instances,state_variant,assignment_time,proof_time" << std::endl;

    std::vector<size_t> instance_counts;
    std::vector<size_t> state_variants = {0}; // Currently only one implementation

    // Define the sweep ranges
    if (quick_mode) {
        // Quick mode for testing - just a few small values
        instance_counts = {1, 2, 4};
    } else {
        // Full benchmark - powers of 2
        for (size_t i = 1; i <= 128; i *= 2) {
            instance_counts.push_back(i);
        }
    }

    // Run benchmarks for each combination
    for (size_t instances : instance_counts) {
        for (size_t variant : state_variants) {
            std::cout << "Running keccak_permute_wide benchmark with instances=" << instances
                      << ", variant=" << variant << "..." << std::endl;

            auto [assignment_time, proof_time] = benchmark_keccak_permute_wide<field_type>(instances, variant);

            // Format benchmark result
            std::string result =
                std::to_string(instances) + "," +
                std::to_string(variant) + "," +
                std::to_string(std::chrono::duration_cast<std::chrono::microseconds>(assignment_time).count()) + "," +
                std::to_string(std::chrono::duration_cast<std::chrono::microseconds>(proof_time).count());

            // Output to both console and file
            std::cout << result << std::endl;
            file_out << result << std::endl;

            // Flush file buffer to ensure data is written even if program crashes
            file_out.flush();
        }
    }

    file_out.close();
    std::cout << "Benchmark results saved to " << output_file << std::endl;
}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

// , *boost::unit_test::disabled()
BOOST_AUTO_TEST_CASE(blueprint_plonk_hashes_keccak_benchmarks) {
    bool quick_mode = false;
    std::string round_output_file = "keccak_round_benchmarks.csv";
    std::string permute_wide_output_file = "keccak_permute_wide_benchmarks.csv";
    bool run_round = false;
    bool run_permute_wide = false;

    for (int i = 1; i < boost::unit_test::framework::master_test_suite().argc; ++i) {
        std::string arg = boost::unit_test::framework::master_test_suite().argv[i];
        if (arg == "--quick" || arg == "-q") {
            quick_mode = true;
        } else if (arg == "--round-output" || arg == "-ro") {
            if (i + 1 < boost::unit_test::framework::master_test_suite().argc) {
                round_output_file = boost::unit_test::framework::master_test_suite().argv[++i];
            }
        } else if (arg == "--permute-wide-output" || arg == "-po") {
            if (i + 1 < boost::unit_test::framework::master_test_suite().argc) {
                permute_wide_output_file = boost::unit_test::framework::master_test_suite().argv[++i];
            }
        } else if (arg == "--run-round" || arg == "-rr") {
            run_round = true;
        } else if (arg == "--run-permute-wide" || arg == "-rp") {
            run_permute_wide = true;
        }
    }

    // If neither is specified, run both
    if (!run_round && !run_permute_wide) {
        run_round = true;
        run_permute_wide = true;
    }

    std::cout << "Running benchmarks with quick_mode=" << (quick_mode ? "true" : "false") << std::endl;

    if (run_round) {
        run_keccak_round_benchmarks(quick_mode, round_output_file);
    }

    if (run_permute_wide) {
        run_keccak_permute_wide_benchmarks(quick_mode, permute_wide_output_file);
    }
}

BOOST_AUTO_TEST_SUITE_END()
