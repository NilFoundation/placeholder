//---------------------------------------------------------------------------//
// Copyright (c) 2023 Elena Tatuzova <e.tatuzova@nil.foundation>
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
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
#ifndef KZG_EVM_VERIFIER_GEN_HPP
#define KZG_EVM_VERIFIER_GEN_HPP

#include <cstddef>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <string>
#include <vector>

#include <boost/algorithm/string.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/gate.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/lookup_constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/lookup_gate.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/table_description.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>

namespace nil {
    namespace blueprint {
        template<typename PlaceholderParams>
        class kzg_evm_verifier_printer {
            using common_data_type = typename nil::crypto3::zk::snark::placeholder_public_preprocessor<
                typename PlaceholderParams::field_type,
                PlaceholderParams
            >::preprocessed_data_type::common_data_type;

            using variable_type = nil::crypto3::zk::snark::plonk_variable<typename PlaceholderParams::field_type::value_type>;
            using constraint_type = nil::crypto3::zk::snark::plonk_constraint<typename PlaceholderParams::field_type>;
            using lookup_constraint_type = nil::crypto3::zk::snark::plonk_lookup_constraint<typename PlaceholderParams::field_type>;
            using gate_type = nil::crypto3::zk::snark::plonk_gate<typename PlaceholderParams::field_type, constraint_type>;
            using lookup_gate_type = nil::crypto3::zk::snark::plonk_lookup_gate<typename PlaceholderParams::field_type, lookup_constraint_type>;
            using variable_indices_type = std::map<nil::crypto3::zk::snark::plonk_variable<typename PlaceholderParams::field_type::value_type>, std::size_t>;
            using columns_rotations_type = std::vector<std::set<int>>;

        public:
            kzg_evm_verifier_printer(
                const typename PlaceholderParams::constraint_system_type &constraint_system,
                const common_data_type &common_data,
                const std::string &folder_name
            )
                : _constraint_system(constraint_system)
                , _common_data(common_data)
                , _folder_name(folder_name)
                , _desc(common_data.desc)
                , _permutation_size(common_data.permuted_columns.size())
                , _commitment_params(common_data.commitment_params) {
                std::size_t found = folder_name.rfind('/');
                if (found == std::string::npos) {
                    _test_name = folder_name;
                } else {
                    _test_name = folder_name.substr(found + 1);
                }
            }

            void print() {
                std::filesystem::create_directories(_folder_name);
                std::ofstream out;

                auto stub_verifier = STUB_VERIFIER_TEMPLATE;
                auto stub_permutation_argument = STUB_PERMUTATION_ARGUMENT_TEMPLATE;
                auto stub_gate_argument = STUB_GATE_ARGUMENT_TEMPLATE;
                auto stub_commitment = STUB_COMMITMENT_TEMPLATE;
                auto stub_lookup_argument = STUB_LOOKUP_ARGUMENT_TEMPLATE;

                boost::replace_all(stub_verifier, "$TEST_NAME$", _test_name);
                boost::replace_all(stub_permutation_argument, "$TEST_NAME$", _test_name);
                boost::replace_all(stub_gate_argument, "$TEST_NAME$", _test_name);
                boost::replace_all(stub_commitment, "$TEST_NAME$", _test_name);
                boost::replace_all(stub_lookup_argument, "$TEST_NAME$", _test_name);

                out.open(_folder_name + "/modular_verifier.sol");
                out << LICENSE;
                out << stub_verifier;
                out.close();

                out.open(_folder_name + "/permutation_argument.sol");
                out << LICENSE;
                out << stub_permutation_argument;
                out.close();

                out.open(_folder_name + "/gate_argument.sol");
                out << LICENSE;
                out << stub_gate_argument;
                out.close();

                out.open(_folder_name + "/commitment.sol");
                out << LICENSE;
                out << stub_commitment;
                out.close();

                out.open(_folder_name + "/lookup_argument.sol");
                out << LICENSE;
                out << stub_lookup_argument;
                out.close();
            }

        private:
            inline static const std::string LICENSE = R"(// SPDX-License-Identifier: Apache-2.0.
//---------------------------------------------------------------------------//
// Copyright (c) 2024 Generated by zkEVM-transpiler
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
)";

            inline static const std::string STUB_VERIFIER_TEMPLATE = R"(pragma solidity >=0.8.4;

import "../../interfaces/modular_verifier.sol";

contract modular_verifier_$TEST_NAME$ is IModularVerifier {
        function initialize(
//        address permutation_argument_address,
        address lookup_argument_address,
        address gate_argument_address,
        address commitment_contract_address
    ) public{
    }

    function verify(
        bytes calldata blob,
        uint256[] calldata public_input
    ) public returns (bool result) {
        emit VerificationResult(false);
        return false;
    }
}
)";

            inline static const std::string STUB_PERMUTATION_ARGUMENT_TEMPLATE = R"(pragma solidity >=0.8.4;

library modular_permutation_argument_$TEST_NAME$ {
}
)";

            inline static const std::string STUB_GATE_ARGUMENT_TEMPLATE = R"(pragma solidity >=0.8.4;

library modular_gate_argument_$TEST_NAME$ {
}
)";

            inline static const std::string STUB_COMMITMENT_TEMPLATE = R"(pragma solidity >=0.8.4;

library modular_commitment_scheme_$TEST_NAME$ {
}
)";

            inline static const std::string STUB_LOOKUP_ARGUMENT_TEMPLATE = R"(pragma solidity >=0.8.4;

library modular_lookup_argument_$TEST_NAME$ {
}
)";

            const typename PlaceholderParams::constraint_system_type &_constraint_system;
            const common_data_type &_common_data;
            std::string _folder_name;
            const zk::snark::plonk_table_description<typename PlaceholderParams::field_type> _desc;
            std::size_t _permutation_size;
            const typename PlaceholderParams::commitment_scheme_type::params_type &_commitment_params;

            std::string _test_name;
        };
    }
}

#endif // KZG_EVM_VERIFIER_GEN_HPP
