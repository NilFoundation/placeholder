//---------------------------------------------------------------------------//
// Copyright (c) 2025 Dmitrii Tabalin <d.tabalin@nil.foundation>
// Copyright (c) 2025 Martun Karapetyan <martun@nil.foundation>
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

#ifndef CRYPTO3_ZK_CACHED_ASSIGNMENT_TABLE_HPP
#define CRYPTO3_ZK_CACHED_ASSIGNMENT_TABLE_HPP

#include <unordered_map>
#include <memory>
#include <utility>
#include <stdexcept>
#include <boost/functional/hash.hpp>

#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/polynomial_dfs.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/bench/scoped_profiler.hpp>

namespace nil::crypto3::zk::snark {

    // Currently we store the value of given variable without any rotations in the cache, to same memory.
    // We may consider to save all the rotations, if that seems to be faster in the future.
    template<typename FieldType>
    class cached_assignment_table {
    public:
        using value_type = typename FieldType::value_type;
        using polynomial_type = math::polynomial<value_type>;
        using polynomial_dfs_type = math::polynomial_dfs<value_type>;
        using domain_type = math::evaluation_domain<FieldType>;
        using plonk_polynomial_dfs_table = zk::snark::plonk_polynomial_dfs_table<FieldType>;
        using variable_type = zk::snark::plonk_variable<polynomial_dfs_type>;
        using var_without_rotation_type = zk::snark::plonk_variable_without_rotation<polynomial_dfs_type>;

        using var_and_size_pair_type = std::pair<var_without_rotation_type, std::size_t>;

        cached_assignment_table(
                std::shared_ptr<plonk_polynomial_dfs_table> table,
                const polynomial_dfs_type& mask_assignment,
                const polynomial_dfs_type& lagrange_0)
            : _original_domain_size(mask_assignment.size())
            , _domain(get_domain(_original_domain_size)) {

            cache_assignment_table_in_coefficients_form(table, mask_assignment, lagrange_0);
        }

        void cache_assignment_table_in_coefficients_form(
                std::shared_ptr<plonk_polynomial_dfs_table> table,
                const polynomial_dfs_type& mask_assignment,
                const polynomial_dfs_type& lagrange_0) {

            // Copy all column values to a single vector.
            std::vector<polynomial_dfs_type> all_columns;
            all_columns.reserve(table->size());
            all_columns.insert(all_columns.end(), table->witnesses().begin(), table->witnesses().end());
            all_columns.insert(all_columns.end(), table->public_inputs().begin(), table->public_inputs().end());
            all_columns.insert(all_columns.end(), table->constants().begin(), table->constants().end());
            all_columns.insert(all_columns.end(), table->selectors().begin(), table->selectors().end());

            // Convert everything to coefficients form.
            std::vector<polynomial_type> table_coeffs =
                math::polynomial_batch_to_coefficients<FieldType>(std::move(all_columns), _domain);

            size_t idx = 0;
            for (size_t i = 0; i < table->witnesses_amount(); ++i) {
                var_without_rotation_type v(i, var_without_rotation_type::column_type::witness);
                _assignment_table_coefficients[v] = std::make_shared<polynomial_type>(
                     std::move(table_coeffs[idx]));
                idx++;
            }
            for (size_t i = 0; i < table->public_inputs_amount(); ++i) {
                var_without_rotation_type v(i, var_without_rotation_type::column_type::public_input);
                _assignment_table_coefficients[v] = std::make_shared<polynomial_type>(
                     std::move(table_coeffs[idx]));
                idx++;
            }
            for (size_t i = 0; i < table->constants_amount(); ++i) {
                var_without_rotation_type v(i, var_without_rotation_type::column_type::constant);
                _assignment_table_coefficients[v] = std::make_shared<polynomial_type>(
                     std::move(table_coeffs[idx]));
                idx++;
            }
            for (size_t i = 0; i < table->selectors_amount(); ++i) {
                var_without_rotation_type v(i, var_without_rotation_type::column_type::selector);
                _assignment_table_coefficients[v] = std::make_shared<polynomial_type>(
                     std::move(table_coeffs[idx]));
                idx++;
            }

            // Now create coefficients forms for special selectors.
            var_without_rotation_type v_all_rows(
                PLONK_SPECIAL_SELECTOR_ALL_USABLE_ROWS_SELECTED,
                var_without_rotation_type::column_type::selector);
            _assignment_table_coefficients[v_all_rows] = std::make_shared<polynomial_type>(
                mask_assignment.coefficients(_domain));

            var_without_rotation_type v_all_non_first_rows(
                PLONK_SPECIAL_SELECTOR_ALL_NON_FIRST_USABLE_ROWS_SELECTED,
                var_without_rotation_type::column_type::selector);
            _assignment_table_coefficients[v_all_non_first_rows] = std::make_shared<polynomial_type>(
                (mask_assignment - lagrange_0).coefficients(_domain));
        }

        cached_assignment_table(const cached_assignment_table&) = default;
        cached_assignment_table &operator=(const cached_assignment_table&) = default;

        size_t get_original_domain_size() const {
            return _original_domain_size;
        }

        void ensure_domain(std::size_t size) {
            if (!_domain_cache.contains(size)) {
                _domain_cache[size] = math::make_evaluation_domain<FieldType>(size);
            }
        }

        std::shared_ptr<domain_type> get_domain(std::size_t size) {
            auto it = _domain_cache.find(size);
            if (it != _domain_cache.end()) {
                return it->second;
            }
            auto new_domain = math::make_evaluation_domain<FieldType>(size);
            _domain_cache[size] = new_domain;
            return new_domain;
        }

        void ensure_cache(const std::set<variable_type> &variables, std::size_t size) {
            TAGGED_PROFILE_SCOPE("{low level} FFT",
                                 "Ensure cache for {} variables, size {}",
                                 variables.size(), size);

            if (variables.size() == 0)
                return;

            if (_original_domain_size > size) {
                throw std::invalid_argument(
                    "Column size is more than the requested size");
            }
            ensure_domain(size);

            // Ensure we have the required variable in the cache with rotation = 0.
            std::set<var_without_rotation_type> new_vars_set;
            std::vector<variable_type> new_variables_with_rotation;
            for (const auto &v_with_rotation : variables) {
                if (is_cached(v_with_rotation, size))
                    continue;

                var_without_rotation_type v(v_with_rotation);
                variable_type v_no_rotataion = v_with_rotation;
                v_no_rotataion.rotation = 0;

                if (v_with_rotation.rotation != 0) {
                    new_variables_with_rotation.push_back(v_with_rotation);
                    _cache[var_and_size_pair_type(v, size)][v_with_rotation.rotation] = nullptr;
                }

                if (!is_cached(v_no_rotataion, size) && !new_vars_set.contains(v)) {
                    new_vars_set.insert(v);
                    _cache[var_and_size_pair_type(v, size)][0] = nullptr;
                }
            }

            std::vector<var_without_rotation_type> new_vars(new_vars_set.begin(), new_vars_set.end());

            parallel_for(
                0, new_vars.size(),
                [&new_vars, size, this](std::size_t i) {
                    // Here we take from _assignment_table_coefficients the variable value
                    // without rotation.
                    auto value_dfs = std::make_shared<polynomial_dfs_type>();
                    value_dfs->from_coefficients(
                        *_assignment_table_coefficients[new_vars[i]], get_domain(size));
                    _cache[std::make_pair(new_vars[i], size)][0] = value_dfs;
                },
                ThreadPool::PoolLevel::HIGH);

            // Ensure we have the required variable in the cache with required rotation.
            parallel_for(
                0, new_variables_with_rotation.size(),
                [&new_variables_with_rotation, size, this](std::size_t i) {
                    auto v_with_rotation = new_variables_with_rotation[i];
                    var_without_rotation_type v(v_with_rotation);

                    _cache[var_and_size_pair_type(v, size)][v_with_rotation.rotation] =
                        std::make_shared<polynomial_dfs_type>(
                            math::polynomial_shift(*_cache[var_and_size_pair_type(v, size)][0],
                                v_with_rotation.rotation, this->_original_domain_size));
                },
                ThreadPool::PoolLevel::HIGH);
        }

        bool is_cached(const variable_type& v, std::size_t size) const {
            var_without_rotation_type v_no_rot(v);
            const auto key = std::make_pair(v_no_rot, size);
            return _cache.contains(key) && _cache.at(key).contains(v.rotation);
        }

        // Ensure the value is cached before calling this function. We intentionally cannot
        // create the variable value inside this function, if it does not exist, because it's much harder
        // in a multi-threaded invironment.
        std::shared_ptr<polynomial_dfs_type> get(const variable_type &v_with_rotation, std::size_t size) const {
            var_without_rotation_type v(v_with_rotation);
            const auto key = std::make_pair(v_with_rotation, size);
            return _cache.at(key).at(v_with_rotation.rotation);
        }

    private:
        struct var_and_size_pair_hash {
            std::size_t operator()(const var_and_size_pair_type& v) const {
                auto v_hash = boost::hash_value(v.first.index);
                boost::hash_combine(v_hash, v.first.type);
                boost::hash_combine(v_hash, v.second);
                return v_hash;
            }
        };

        std::unordered_map<std::size_t, std::shared_ptr<domain_type>> _domain_cache;

        // Second map key is the rotation used.
        std::unordered_map<var_and_size_pair_type, std::unordered_map<int, std::shared_ptr<polynomial_dfs_type>>,
                           var_and_size_pair_hash> _cache;

        // The whole assignment table and special selectors in the coefficients form.
        std::unordered_map<var_without_rotation_type, std::shared_ptr<polynomial_type>> _assignment_table_coefficients;

        std::size_t _original_domain_size;
        std::shared_ptr<domain_type> _domain;

    };
} // namespace nil::crypto3::zk::snark

#endif // CRYPTO3_ZK_CACHED_ASSIGNMENT_TABLE_HPP
