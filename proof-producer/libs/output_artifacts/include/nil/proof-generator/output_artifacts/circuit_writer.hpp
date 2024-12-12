//---------------------------------------------------------------------------//
// Copyright (c) 2024 Daniil Kogtev <oclaw@nil.foundation>
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

#ifndef PROOF_GENERATOR_CIRCUIT_WRITER_HPP
#define PROOF_GENERATOR_CIRCUIT_WRITER_HPP

#include <ostream>
#include <vector>

#include <nil/crypto3/marshalling/zk/types/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>


namespace nil {
    namespace proof_generator {


        template <typename Endianness, typename BlueprintField> 
        class circuit_writer {
                public:
                    using TTypeBase = nil::crypto3::marshalling::field_type<Endianness>;
                    using Circuit = nil::crypto3::zk::snark::plonk_constraint_system<BlueprintField>;

                    circuit_writer() = delete;

                    /**
                    * @brief Write circuit serialized into binary to output file.
                    */
                    static void write_binary_circuit(
                            std::ostream& out,
                            const Circuit& circuit,
                            const std::vector<std::size_t>& public_input_column_sizes) {

                        namespace marshalling_types = nil::crypto3::marshalling::types;
                        using value_marshalling_type = marshalling_types::plonk_constraint_system<TTypeBase, Circuit>;

                        // fill public input sizes
                        marshalling_types::public_input_sizes_type<TTypeBase> public_input_sizes;
                        using public_input_size_type = typename marshalling_types::public_input_sizes_type<TTypeBase>::element_type;

                        const auto public_input_size = public_input_column_sizes.size();
                        for (const auto i : public_input_column_sizes) {
                            public_input_sizes.value().push_back(public_input_size_type(i));
                        }

                        auto filled_val =
                            value_marshalling_type(std::make_tuple(
                                marshalling_types::fill_plonk_gates<Endianness, typename Circuit::gates_container_type::value_type>(circuit.gates()),
                                marshalling_types::fill_plonk_copy_constraints<Endianness, typename Circuit::field_type>(circuit.copy_constraints()),
                                marshalling_types::fill_plonk_lookup_gates<Endianness, typename Circuit::lookup_gates_container_type::value_type>(circuit.lookup_gates()),
                                marshalling_types::fill_plonk_lookup_tables<Endianness, typename Circuit::lookup_tables_type::value_type>(circuit.lookup_tables()),
                                public_input_sizes
                        ));


                        std::vector<std::uint8_t> cv(filled_val.length(), 0x00);
                        auto iter = cv.begin();
                        auto const status = filled_val.write(iter, cv.size());
                        assert(status == nil::crypto3::marshalling::status_type::success);
                        out.write(reinterpret_cast<char*>(cv.data()), cv.size());
                    }
        };        

    } // namespace proof_generator
} // namespace nil


#endif // PROOF_GENERATOR_CIRCUIT_WRITER_HPP



