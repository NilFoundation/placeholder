//---------------------------------------------------------------------------//
// Copyright (c) 2025 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#pragma once

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/table_description.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/gate.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/lookup_gate.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/copy_constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/lookup_constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>

namespace nil::blueprint {
    template<typename FieldType>
    std::string constrain_system_stat(
        const circuit<crypto3::zk::snark::plonk_constraint_system<FieldType>>& bp
    ) {
        std::stringstream ss;

        ss << "Constraint system statistics:" << std::endl;
        ss << "\tNumber of gates: " << bp.gates().size() << std::endl;
        std::size_t total_constraints = 0;
        for( std::size_t i = 0; i < bp.gates().size(); i++ ){
            total_constraints += bp.gates()[i].constraints.size();
        }
        ss << "\t\tTotal amount of constraints: " << total_constraints << std::endl;
        ss << "\t\tMaximum constraints degree: " << bp.max_gates_degree() << std::endl;
        ss << "\tNumber of lookup gates: " << bp.lookup_gates().size() << std::endl;
        std::size_t total_lookup_constraints = 0;
        std::map<std::string, std::size_t> lookup_constraints_count;
        for( std::size_t i = 0; i < bp.lookup_gates().size(); i++ ){
            total_lookup_constraints += bp.lookup_gates()[i].constraints.size();
            for( const auto &constraint : bp.lookup_gates()[i].constraints ){
                const auto table_name = bp.get_reserved_indices_right().at(constraint.table_id);
                lookup_constraints_count[table_name]++;
            }
        }
        ss << "\t\tTotal amount of lookup constraints: " << total_lookup_constraints << std::endl;
        ss << "\t\tMaximum lookup constraints degree: " << bp.max_lookup_gates_degree() << std::endl;
        ss << "\tLookup constraints count by table:" << std::endl;
        for( const auto &pair : lookup_constraints_count ){
            ss << "\t\t" << pair.first << ": " << pair.second << std::endl;
        }
        return ss.str();
    }
}