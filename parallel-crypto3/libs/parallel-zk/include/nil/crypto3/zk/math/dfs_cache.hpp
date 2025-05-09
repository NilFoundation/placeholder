//---------------------------------------------------------------------------//
// Copyright (c) 2025 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#ifndef PARALLEL_CRYPTO3_ZK_POLYNOMIAL_DFS_CACHE_HPP
#define PARALLEL_CRYPTO3_ZK_POLYNOMIAL_DFS_CACHE_HPP

#ifdef CRYPTO3_MATH_POLYNOMIAL_DFS_CACHE_HPP
#error "You're mixing parallel and non-parallel crypto3 versions"
#endif

#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <utility>
#include <stdexcept>
#include <cstdint>

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
    struct dfs_cache {
        using value_type = typename FieldType::value_type;
        using polynomial_type = math::polynomial<value_type>;
        using polynomial_dfs_type = math::polynomial_dfs<value_type>;
        using domain_type = math::evaluation_domain<FieldType>;
        using plonk_polynomial_dfs_table = zk::snark::plonk_polynomial_dfs_table<FieldType>;
        using variable_type = zk::snark::plonk_variable<polynomial_dfs_type>;
        using var_without_rotation_type = zk::snark::plonk_variable_without_rotation<polynomial_dfs_type>;

        using var_and_size_pair_type = std::pair<var_without_rotation_type, std::size_t>;

        struct var_and_size_pair_hash {
            std::size_t operator()(const var_and_size_pair_type& v) const {
                auto v_hash = boost::hash_value(v.first.index);
                boost::hash_combine(v_hash, v.first.type);
                boost::hash_combine(v_hash, v.second);
                return v_hash;
            }
        };

        // TODO(martun): remove the table from here, immediately store everything in
        // coefficients form in ifft cache.
        std::shared_ptr<plonk_polynomial_dfs_table> table;
        polynomial_dfs_type mask_assignment;
        polynomial_dfs_type lagrange_0;

        std::unordered_map<std::size_t, std::shared_ptr<domain_type>> domain_cache;
        // Second map is the rotation used.
        std::unordered_map<var_and_size_pair_type, std::unordered_map<int, std::shared_ptr<polynomial_dfs_type>>,
                           var_and_size_pair_hash> cache;

        std::unordered_map<var_without_rotation_type, std::shared_ptr<polynomial_type>> ifft_cache;

        std::size_t original_domain_size;
        std::shared_ptr<domain_type> domain;

        dfs_cache(std::shared_ptr<plonk_polynomial_dfs_table> table,
                  const polynomial_dfs_type& mask_assignment, const polynomial_dfs_type& lagrange_0)
            : table(table)
            , mask_assignment(mask_assignment)
            , lagrange_0(lagrange_0)
            , original_domain_size(mask_assignment.size())
            , domain(get_domain(original_domain_size)) {}

        dfs_cache(const dfs_cache&) = default;
        dfs_cache &operator=(const dfs_cache&) = default;

        size_t get_original_domain_size() const {
            return original_domain_size;
        }

        void ensure_domain(std::size_t size) {
            if (!domain_cache.contains(size)) {
                domain_cache[size] = math::make_evaluation_domain<FieldType>(size);
            }
        }

        std::shared_ptr<domain_type> get_domain(std::size_t size) {
            auto it = domain_cache.find(size);
            if (it != domain_cache.end()) {
                return it->second;
            }
            auto new_domain = math::make_evaluation_domain<FieldType>(size);
            domain_cache[size] = new_domain;
            return new_domain;
        }

        void ensure_cache(const std::set<variable_type> &variables, std::size_t size) {
            PROFILE_SCOPE("Ensure cache");

            if (variables.size() == 0)
                return;
            if (original_domain_size > size) {
                throw std::invalid_argument(
                    "Column size is more than the requested "
                    "size");
            }
            ensure_domain(size);
            std::set<var_without_rotation_type> new_vars_ifft_set;

            for (const auto &v_with_rotation : variables) {
                var_without_rotation_type v(v_with_rotation);

                if (is_cached_ifft(v) || new_vars_ifft_set.contains(v)) {
                    continue;
                }
                new_vars_ifft_set.insert(v);
                ifft_cache[v] = nullptr;
            }

            std::vector<var_without_rotation_type> new_vars_ifft(new_vars_ifft_set.begin(), new_vars_ifft_set.end());

            parallel_for(
                0, new_vars_ifft.size(),
                [&new_vars_ifft, this](std::size_t i) {
                    // We should cache the special selector values as well.
                    if (new_vars_ifft[i].type == var_without_rotation_type::column_type::selector && 
                        new_vars_ifft[i].index >= zk::snark::PLONK_MAX_SELECTOR_ID) {

                        if (new_vars_ifft[i].index == PLONK_SPECIAL_SELECTOR_ALL_USABLE_ROWS_SELECTED )
                            ifft_cache[new_vars_ifft[i]] = std::make_shared<polynomial_type>(
                                mask_assignment.coefficients(domain));
                        else if (new_vars_ifft[i].index == PLONK_SPECIAL_SELECTOR_ALL_NON_FIRST_USABLE_ROWS_SELECTED)
                            ifft_cache[new_vars_ifft[i]] = std::make_shared<polynomial_type>(
                                (mask_assignment - lagrange_0).coefficients(domain));
                        else if (new_vars_ifft[i].index == PLONK_SPECIAL_SELECTOR_ALL_ROWS_SELECTED)
                            throw std::logic_error("You should not multiply with the selector for all rows.");
                        else
                            throw std::logic_error("Unknown special selector.");
                    }
                    else {
                        ensure_ifft_cache_for_standard_variable(new_vars_ifft[i]);
                    }
                },
                ThreadPool::PoolLevel::HIGH);

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
                    cache[var_and_size_pair_type(v, size)][v_with_rotation.rotation] = nullptr;
                }

                if (!is_cached(v_no_rotataion, size) && !new_vars_set.contains(v)) {
                    new_vars_set.insert(v);
                    cache[var_and_size_pair_type(v, size)][0] = nullptr;
                }
            }

            std::vector<var_without_rotation_type> new_vars(new_vars_set.begin(), new_vars_set.end());

            parallel_for(
                0, new_vars.size(),
                [&new_vars, size, this](std::size_t i) {
                    // Here we take from ifft_cache the variable value without rotation.
                    auto value_dfs = std::make_shared<polynomial_dfs_type>();
                    value_dfs->from_coefficients(*ifft_cache[new_vars[i]], get_domain(size));
                    cache[std::make_pair(new_vars[i], size)][0] = value_dfs;
                },
                ThreadPool::PoolLevel::HIGH);

            // Ensure we have the required variable in the cache with required rotation.
            parallel_for(
                0, new_variables_with_rotation.size(),
                [&new_variables_with_rotation, size, this](std::size_t i) {
                    auto v_with_rotation = new_variables_with_rotation[i];
                    var_without_rotation_type v(v_with_rotation);
                    cache[var_and_size_pair_type(v, size)][v_with_rotation.rotation] = 
                        std::make_shared<polynomial_dfs_type>(
                            math::polynomial_shift(*cache[var_and_size_pair_type(v, size)][0],
                                v_with_rotation.rotation, this->original_domain_size));
                },
                ThreadPool::PoolLevel::HIGH);
        }

        // We have a column in the table for this variable.
        void ensure_ifft_cache_for_standard_variable(const var_without_rotation_type &var) {
            auto original_column = table->get_variable_value_without_rotation(var);
            ifft_cache[var] = std::make_shared<polynomial_type>(
                original_column.coefficients(domain));
        }

        bool is_cached_ifft(const var_without_rotation_type& v) const {
            return ifft_cache.contains(v);
        }
        bool is_cached(const variable_type& v, std::size_t size) const {
            var_without_rotation_type v_no_rot(v);
            const auto key = std::make_pair(v_no_rot, size);
            return cache.contains(key) && cache.at(key).contains(v.rotation);
        }

        // Ensure the value is cached before calling this function. We intentionally cannot
        // create the variable value inside this function, if it does not exist, because it's much harder
        // in a multi-threaded invironment.
        std::shared_ptr<polynomial_dfs_type> get(const variable_type &v_with_rotation, std::size_t size) const {
            var_without_rotation_type v(v_with_rotation);
            const auto key = std::make_pair(v_with_rotation, size);
            return cache.at(key).at(v_with_rotation.rotation);
        }
    };
} // namespace nil::crypto3::zk::snark

#endif // PARALLEL_CRYPTO3_ZK_POLYNOMIAL_DFS_CACHE_HPP
