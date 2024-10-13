//---------------------------------------------------------------------------//
// Copyright (c) 2024 Valeh Farzaliyev <estoniaa@nil.foundation>
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
// @file Declaration of interfaces for FRI verification linear interpolation component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_DFRI_LINEAR_CHECK_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_DFRI_LINEAR_CHECK_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            // 
            // Input: theta, x, {xi}, {y_i}, {z_ij}
            // Output: sum theta^l (yi - z_ij)/(x - xi_j)
            // DOES NOT CHECK THAT x = xi
            template<typename ArithmetizationType, typename BlueprintFieldType>
            class dfri_linear_check;

            template<typename BlueprintFieldType>
            class dfri_linear_check<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType>
                : public plonk_component<BlueprintFieldType> {

            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                    std::uint32_t num_gates;
                public:
                    std::size_t m;
                    std::size_t witness_amount;
                    std::uint32_t gates_amount() const override {
                        return num_gates;
                    }

                    gate_manifest_type(std::size_t witness_amount_, std::size_t m_) :m(m_), witness_amount(witness_amount_) {
                        num_gates = dfri_linear_check::get_gates_amount(witness_amount, m);
                    };

                    bool operator<(const component_gate_manifest *other) const override {
                        return witness_amount < dynamic_cast<const gate_manifest_type*>(other)->witness_amount && 
                                m < dynamic_cast<const gate_manifest_type*>(other)->m;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t m) {
                    gate_manifest manifest = gate_manifest(gate_manifest_type(witness_amount, m));
                    return manifest;
                }

                static manifest_type get_manifest() {
                    manifest_type manifest =
                        manifest_type(std::shared_ptr<manifest_param>(new manifest_range_param(3, 150)), false);
                    return manifest;
                }

                const std::size_t m;
                const std::vector<std::pair<std::size_t, std::size_t>> eval_map;

                const std::vector<std::pair<std::size_t, std::size_t>> optimal_layout = search_optimal_layout(this->witness_amount(), m);

                const std::vector<std::array<std::pair<std::size_t, std::size_t>, 9>> fullconfig = full_configuration(this->witness_amount(), 0, m, optimal_layout);

                static std::size_t get_rows_amount(std::size_t witness_amount, std::size_t m) {

                    auto optimal_layout = search_optimal_layout(witness_amount, m);
                    std::size_t rows = 0;
                    for(const auto &[k, w] : optimal_layout){
                        rows = std::max(rows, k * static_cast<std::size_t>(std::ceil(9.0 / w)));
                    }
                    return rows;
                }

                static std::size_t get_gates_amount(std::size_t witness_amount, std::size_t m) {

                    auto optimal_layout = search_optimal_layout(witness_amount, m);
                    return optimal_layout.size();
                }

                static std::vector<std::pair<std::size_t, std::size_t>> search_optimal_layout(std::size_t witness_amount, std::size_t m, bool optimized = true){
                    
                    std::vector<std::pair<std::size_t, std::size_t>> trace;
                    if(optimized){
                        std::vector<std::vector<std::size_t>> best_rows;
                        std::vector<std::vector<std::size_t>> gate_amounts;
                        best_rows.resize(m+1);
                        gate_amounts.resize(m+1);
                        std::size_t nine = 9;
                        for(std::size_t i = 0; i <= m; i++){
                            best_rows[i] = std::vector<std::size_t>(witness_amount + 1);
                            gate_amounts[i] = std::vector<std::size_t>(witness_amount + 1);
                            std::fill(best_rows[i].begin(), best_rows[i].end(), 9999);
                            std::fill(gate_amounts[i].begin(), gate_amounts[i].end(), 0);
                            if(i > 0){
                                for(std::size_t j = 3; j <= std::min(witness_amount, nine); j++){
                                    best_rows[i][j] =  i * (std::size_t) std::ceil(9.0 / j);    
                                    gate_amounts[i][j] = 1;
                                }
                            }
                        }
                        std::fill(best_rows[0].begin(), best_rows[0].end(), 0);
                        
                        
                        std::map<std::pair<std::size_t, std::size_t>,std::pair<std::size_t, std::size_t>> config;
                        
                        for(std::size_t i = 1; i < witness_amount; i++){
                            config[{0, i}] = std::make_pair(0, i);
                        }
                        for(std::size_t k = 1; k <= m; k++){
                            for(std::size_t i = 1; i < 10; i++){
                                config[{k, i}] = std::make_pair(k, i);
                            }
                            for(std::size_t i = 10; i <= witness_amount; i++){
                                for(std::size_t j = 1; j <= 9; j++){
                                    for(std::size_t l = 0; l <= k; l++){
                                        std::size_t row = std::max(best_rows[k - l][i - j], best_rows[l][j]);
                                        auto gate_amount = gate_amounts[k-l][i - j] + gate_amounts[l][j];
                                        if(row < best_rows[k][i] || (row == best_rows[k][i] && gate_amount <= gate_amounts[k][i])){
                                            config[{k, i}] = std::make_pair(l, j);
                                            best_rows[k][i] = row;
                                            gate_amounts[k][i] = gate_amount;
                                        }
                                    }
                                }
                            }
                        }
                        
                        
                        trace.resize(0);
                        auto _m = m;
                        auto _w = witness_amount;
                        while(_m > 0){
                            trace.push_back(config[{_m, _w}]);
                            _m = _m - trace.back().first;
                            _w = _w - trace.back().second;
                        } 
                        std::sort(trace.begin(), trace.end(), [](const std::pair<std::size_t,std::size_t> &left, const std::pair<std::size_t,std::size_t> &right) {
                            return left.second > right.second;
                        });
                    }
                    else{
                        trace.push_back({m, witness_amount});
                    }
                    return trace;
                }

                const std::size_t gates_amount = get_gates_amount(this->witness_amount(), m);
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), m);
                const std::string component_name = "dfri linear check component";

                struct input_type {
                    var theta;
                    var x;
                    std::vector<var> xi;
                    std::vector<var> y;
                    std::vector<var> z;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> vars;

                        vars.push_back(theta);
                        vars.push_back(x);
                        vars.insert(vars.end(), xi.begin(), xi.end());
                        vars.insert(vars.end(), y.begin(), y.end());
                        vars.insert(vars.end(), z.begin(), z.end());

                        return vars;
                    }
                };

                struct result_type {
                    var output;

                    result_type(const dfri_linear_check &component, std::uint32_t start_row_index) {
                        // BOOST_ASSERT(component.fullconfig.size() == component.m);
                        output = var(component.W(component.fullconfig[component.m-1][8].first),
                                     start_row_index + component.fullconfig[component.m-1][8].second, false, var::column_type::witness);
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {output};
                    }
                };

                static std::array<std::pair<std::size_t, std::size_t>, 9> configure_blocks(std::size_t witness_amount, std::size_t col,
                                                                                           std::size_t row) {

                    std::array<std::pair<std::size_t, std::size_t>, 9> locations;

                    std::size_t r = 0, c = 0;
                    for (std::size_t i = 0; i < 9; i++) {
                        r = row + i / witness_amount;
                        c = col + i % witness_amount;
                        locations[i] = std::make_pair(c, r);
                    }

                    return locations;
                }

                static std::vector<std::array<std::pair<std::size_t, std::size_t>, 9>>
                    full_configuration(std::size_t witness_amount, std::size_t row, std::size_t m, const std::vector<std::pair<std::size_t, std::size_t>> &optimal_layout) {

                    std::vector<std::array<std::pair<std::size_t, std::size_t>, 9>> configs;
                    std::size_t single_block_rows;
                    std::size_t last_col = 0;

                    for(const auto &[k, v] : optimal_layout){
                        single_block_rows = std::ceil(9.0 / v);
                        for (std::size_t i = 0; i < k; i++) {
                            configs.push_back(configure_blocks(v, last_col, row + i * single_block_rows));
                        }
                        last_col += v;
                    }

                    BOOST_ASSERT(last_col <= witness_amount);
                    BOOST_ASSERT(configs.size() == m);
                    return configs;
                }

                template<typename ContainerType>
                dfri_linear_check(ContainerType witness, std::size_t m_,
                                  std::vector<std::pair<std::size_t, std::size_t>> &eval_map_) :
                    component_type(witness, {}, {}, get_manifest()), m(m_), eval_map(eval_map_) {

                    };

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                dfri_linear_check(WitnessContainerType witness, ConstantContainerType constant,
                                  PublicInputContainerType public_input, std::size_t m_,
                                  std::vector<std::pair<std::size_t, std::size_t>> &eval_map_) :
                    component_type(witness, constant, public_input, get_manifest()), m(m_), eval_map(eval_map_) {

                    };

                dfri_linear_check(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    std::size_t m_, std::vector<std::pair<std::size_t, std::size_t>> &eval_map_) :
                    component_type(witnesses, constants, public_inputs, get_manifest()), m(m_), eval_map(eval_map_) {

                    };
            };

            template<typename BlueprintFieldType>
            using plonk_dfri_linear_check =
                dfri_linear_check<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType>;

            template<typename BlueprintFieldType>
            typename plonk_dfri_linear_check<BlueprintFieldType>::result_type generate_assignments(
                const plonk_dfri_linear_check<BlueprintFieldType> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename plonk_dfri_linear_check<BlueprintFieldType>::input_type &instance_input,
                const std::uint32_t start_row_index) {

                using value_type = typename BlueprintFieldType::value_type;
                using var = typename plonk_dfri_linear_check<BlueprintFieldType>::var;

                BOOST_ASSERT(component.fullconfig.size() == component.m);
                BOOST_ASSERT(component.optimal_layout.size() == component.gates_amount);
                BOOST_ASSERT(instance_input.z.size() == component.m);

                std::size_t il, jl;
                value_type x, xi, xsubxiinv, y, z, q, q_new;
                value_type q_last = value_type::zero();
                value_type theta = var_value(assignment, instance_input.theta);

                std::vector<var> reordered_z = {};
                std::vector<std::vector<std::size_t>> z_indices(instance_input.y.size(), std::vector<std::size_t>());
                for(std::size_t l = 0; l < component.m; l++){
                    il = component.eval_map[l].first;
                    jl = component.eval_map[l].second;
                    z_indices[il].push_back(jl);
                }

                for(std::size_t l = 0; l < component.m; l++){
                    il = component.eval_map[l].first;
                    jl = component.eval_map[l].second;
                    std::size_t _index = 0;
                    for(std::size_t i = 0; i < il; i++){
                        _index += z_indices[i].size();
                    }
                    std::size_t j=0;
                    while(jl != z_indices[il][j]){
                        _index++;
                        j++;
                    }
                    reordered_z.push_back(instance_input.z[_index]);
                }

                for (std::size_t l = 0; l < component.m; l++) {
                    il = component.eval_map[component.m - l - 1].first;
                    jl = component.eval_map[component.m - l - 1].second;
                    x = var_value(assignment, instance_input.x);
                    xi = var_value(assignment, instance_input.xi[jl]);
                    xsubxiinv = (x - xi).inversed();
                    y = var_value(assignment, instance_input.y[il]);
                    z = var_value(assignment, reordered_z[component.m - l - 1]);
                    q = (y - z) * xsubxiinv;
                    q_new = q + theta * q_last;

                    assignment.witness(component.W(component.fullconfig[l][0].first),
                                       start_row_index + component.fullconfig[l][0].second) = x;
                    assignment.witness(component.W(component.fullconfig[l][1].first),
                                       start_row_index + component.fullconfig[l][1].second) = xi;
                    assignment.witness(component.W(component.fullconfig[l][2].first),
                                       start_row_index + component.fullconfig[l][2].second) = xsubxiinv;
                    assignment.witness(component.W(component.fullconfig[l][3].first),
                                       start_row_index + component.fullconfig[l][3].second) = y;
                    assignment.witness(component.W(component.fullconfig[l][4].first),
                                       start_row_index + component.fullconfig[l][4].second) = z;
                    assignment.witness(component.W(component.fullconfig[l][5].first),
                                       start_row_index + component.fullconfig[l][5].second) = q;
                    assignment.witness(component.W(component.fullconfig[l][6].first),
                                       start_row_index + component.fullconfig[l][6].second) = theta;
                    assignment.witness(component.W(component.fullconfig[l][7].first),
                                       start_row_index + component.fullconfig[l][7].second) = q_last;
                    assignment.witness(component.W(component.fullconfig[l][8].first),
                                       start_row_index + component.fullconfig[l][8].second) = q_new;

                    q_last = q_new;
                }


                // std::cout << "rows amount: " << component.rows_amount << std::endl;
                return typename plonk_dfri_linear_check<BlueprintFieldType>::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType>
            std::vector<std::size_t>
                generate_gates(const plonk_dfri_linear_check<BlueprintFieldType> &component,
                               circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                               assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                               const typename plonk_dfri_linear_check<BlueprintFieldType>::input_type &instance_input) {

                using var = typename plonk_dfri_linear_check<BlueprintFieldType>::var;

                std::vector<std::size_t> selectors;
                std::size_t last_col = 0;
                for(auto &[k, v] : component.optimal_layout){

                    int shift = (v > 4) ? 0 : -1;
                    auto single_block = plonk_dfri_linear_check<BlueprintFieldType>::configure_blocks(v, last_col, 0);
                    last_col += v;

                    var x = var(component.W(single_block[0].first), static_cast<int>(single_block[0].second + shift));
                    var xi = var(component.W(single_block[1].first), static_cast<int>(single_block[1].second + shift));
                    var xsubxiinv =
                        var(component.W(single_block[2].first), static_cast<int>(single_block[2].second + shift));
                    var y = var(component.W(single_block[3].first), static_cast<int>(single_block[3].second + shift));
                    var z = var(component.W(single_block[4].first), static_cast<int>(single_block[4].second + shift));
                    var q = var(component.W(single_block[5].first), static_cast<int>(single_block[5].second + shift));
                    var theta = var(component.W(single_block[6].first), static_cast<int>(single_block[6].second + shift));
                    var q_last = var(component.W(single_block[7].first), static_cast<int>(single_block[7].second + shift));
                    var q_new = var(component.W(single_block[8].first), static_cast<int>(single_block[8].second + shift));

                    auto constraint_1 = (x - xi) * xsubxiinv - 1;
                    auto constraint_2 = q * (x - xi) - (y - z);
                    auto constraint_3 = q_new - (q_last * theta + q);

                    selectors.push_back(bp.add_gate({constraint_1, constraint_2, constraint_3}));
                }

                return selectors;
            }

            template<typename BlueprintFieldType>
            void generate_copy_constraints(
                const plonk_dfri_linear_check<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename plonk_dfri_linear_check<BlueprintFieldType>::input_type &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_dfri_linear_check<BlueprintFieldType>::var;

                std::size_t il, jl;
                std::vector<var> reordered_z = {};
                std::vector<std::vector<std::size_t>> z_indices(instance_input.y.size(), std::vector<std::size_t>());
                for(std::size_t l = 0; l < component.m; l++){
                    il = component.eval_map[l].first;
                    jl = component.eval_map[l].second;
                    z_indices[il].push_back(jl);
                }
                
                std::size_t cur = 0;
                for(std::size_t l = 0; l < component.m; l++){
                    il = component.eval_map[l].first;
                    jl = component.eval_map[l].second;
                    std::size_t _index = 0;
                    for(std::size_t i = 0; i < il; i++){
                        _index += z_indices[i].size();
                    }
                    std::size_t j=0;
                    while(jl != z_indices[il][j]){
                        _index++;
                        j++;
                    }
                    reordered_z.push_back(instance_input.z[_index]);
                }

                for (std::size_t l = 0; l < component.m; l++) {
                    il = component.eval_map[component.m - l - 1].first;
                    jl = component.eval_map[component.m - l - 1].second;

                    var x = var(component.W(component.fullconfig[l][0].first),
                                static_cast<int>(component.fullconfig[l][0].second + start_row_index), false);
                    var xi = var(component.W(component.fullconfig[l][1].first),
                                 static_cast<int>(component.fullconfig[l][1].second + start_row_index), false);
                    var y = var(component.W(component.fullconfig[l][3].first),
                                static_cast<int>(component.fullconfig[l][3].second + start_row_index), false);
                    var z = var(component.W(component.fullconfig[l][4].first),
                                static_cast<int>(component.fullconfig[l][4].second + start_row_index), false);
                    var theta = var(component.W(component.fullconfig[l][6].first),
                                    static_cast<int>(component.fullconfig[l][6].second + start_row_index), false);
                    var q_last = var(component.W(component.fullconfig[l][7].first),
                                     static_cast<int>(component.fullconfig[l][7].second + start_row_index), false);

                    bp.add_copy_constraint({instance_input.x, x});
                    bp.add_copy_constraint({instance_input.xi[jl], xi});
                    bp.add_copy_constraint({instance_input.y[il], y});
                    bp.add_copy_constraint({reordered_z[component.m - l - 1], z});
                    bp.add_copy_constraint({instance_input.theta, theta});

                    if (l >= 1) {
                        var q_new_old =
                            var(component.W(component.fullconfig[l - 1][8].first),
                                static_cast<int>(component.fullconfig[l - 1][8].second + start_row_index), false);
                        bp.add_copy_constraint({q_last, q_new_old});
                    } else {
                        bp.add_copy_constraint(
                            {q_last, var(component.C(0), start_row_index, false, var::column_type::constant)});
                    }
                }
            }

            template<typename BlueprintFieldType>
            typename plonk_dfri_linear_check<BlueprintFieldType>::result_type generate_circuit(
                const plonk_dfri_linear_check<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename plonk_dfri_linear_check<BlueprintFieldType>::input_type &instance_input,
                const std::size_t start_row_index) {


                generate_assignments_constant(component, bp, assignment, instance_input, start_row_index);

                std::vector<std::size_t> selector_index = generate_gates(component, bp, assignment, instance_input);

                std::size_t single_block_rows;
                std::size_t shift;

                std::size_t sel = 0;
                for(auto &[k, v] : component.optimal_layout){
                    shift = (v > 4) ? 0 : 1;
                    single_block_rows = std::ceil(9.0 / v);
                    for (std::size_t l = 0; l < k; l++) {
                        assignment.enable_selector(selector_index[sel], start_row_index + l * single_block_rows + shift);
                        // std::cout << "enable selector " << selector_index[sel] << " at row " << start_row_index + l * single_block_rows + shift << " for config " << l << std::endl;
                    }
                    sel++;
                }

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_dfri_linear_check<BlueprintFieldType>::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType>
            void generate_assignments_constant(
                const plonk_dfri_linear_check<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename plonk_dfri_linear_check<BlueprintFieldType>::input_type &instance_input,
                const std::uint32_t start_row_index) {

                using value_type = typename BlueprintFieldType::value_type;

                assignment.constant(component.C(0), start_row_index) = 0;
            }

        }    // namespace components
    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_DFRI_LINEAR_CHECK_HPP
