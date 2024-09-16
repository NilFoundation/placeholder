/**
 * @file write_circuits.hpp
 *
 * @brief This file defines functions for writing circuits in binary mode.
 */

#ifndef ZKEMV_FRAMEWORK_LIBS_ASSIGNER_RUNNER_INCLUDE_ZKEVM_FRAMEWORK_ASSIGNER_RUNNER_WRITE_CIRCUITS_HPP_
#define ZKEMV_FRAMEWORK_LIBS_ASSIGNER_RUNNER_INCLUDE_ZKEVM_FRAMEWORK_ASSIGNER_RUNNER_WRITE_CIRCUITS_HPP_

#include <array>
#include <cassert>
#include <cmath>
#include <cstdint>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include "nil/blueprint/blueprint/plonk/assignment.hpp"
#include "nil/blueprint/blueprint/plonk/circuit.hpp"
#include "nil/crypto3/marshalling/algebra/types/field_element.hpp"
#include "nil/crypto3/marshalling/zk/types/plonk/constraint_system.hpp"
#include "nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp"
#include "nil/marshalling/types/integral.hpp"
#include "output_artifacts.hpp"

/**
 * @brief Write circuit serialized into binary to output file.
 */
template<typename Endianness, typename ArithmetizationType, typename BlueprintFieldType>
std::optional<std::string> write_binary_circuit(const nil::blueprint::circuit<ArithmetizationType>& circuit,
                                               const std::vector<std::size_t> public_input_column_sizes,
                                               const std::string& filename) {
    std::ofstream fout(filename, std::ios_base::binary | std::ios_base::out);
    if (!fout.is_open()) {
        return "Cannot open " + filename;
    }
    BOOST_LOG_TRIVIAL(debug) << "writing circuit into file "
                             << filename;

    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using ConstraintSystemType = nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using value_marshalling_type =
        nil::crypto3::marshalling::types::plonk_constraint_system<TTypeBase, ConstraintSystemType>;

    // fill public input sizes
    nil::crypto3::marshalling::types::public_input_sizes_type<TTypeBase> public_input_sizes;
    using public_input_size_type = typename nil::crypto3::marshalling::types::public_input_sizes_type<TTypeBase>::element_type;
    const auto public_input_size = public_input_column_sizes.size();
    for (auto i : public_input_column_sizes) {
        public_input_sizes.value().push_back(public_input_size_type(i));
    }

    auto filled_val =
        value_marshalling_type(std::make_tuple(
            nil::crypto3::marshalling::types::fill_plonk_gates<Endianness, typename ConstraintSystemType::gates_container_type::value_type>(circuit.gates()),
            nil::crypto3::marshalling::types::fill_plonk_copy_constraints<Endianness, typename ConstraintSystemType::field_type>(circuit.copy_constraints()),
            nil::crypto3::marshalling::types::fill_plonk_lookup_gates<Endianness, typename ConstraintSystemType::lookup_gates_container_type::value_type>(circuit.lookup_gates()),
            nil::crypto3::marshalling::types::fill_plonk_lookup_tables<Endianness, typename ConstraintSystemType::lookup_tables_type::value_type>(circuit.lookup_tables()),
            public_input_sizes
    ));

    std::vector<std::uint8_t> cv;
    cv.resize(filled_val.length(), 0x00);
    auto cv_iter = cv.begin();
    nil::marshalling::status_type status = filled_val.write(cv_iter, cv.size());
    fout.write(reinterpret_cast<char*>(cv.data()), cv.size());

    fout.close();
    return {};
}

#endif  // ZKEMV_FRAMEWORK_LIBS_ASSIGNER_RUNNER_INCLUDE_ZKEVM_FRAMEWORK_ASSIGNER_RUNNER_WRITE_CIRCUITS_HPP_
