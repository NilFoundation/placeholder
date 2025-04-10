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

#ifndef PARALLEL_CRYPTO3_MATH_POLYNOMIAL_DFS_CACHE_HPP
#define PARALLEL_CRYPTO3_MATH_POLYNOMIAL_DFS_CACHE_HPP

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

#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/polynomial/polynomial_dfs.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

namespace nil {
    namespace crypto3 {
        namespace math {

            template<typename FieldType>
            struct dfs_cache {
                using value_type = typename FieldType::value_type;
                using polynomial_type = polynomial_dfs<value_type>;
                using domain_type = evaluation_domain<FieldType>;
                using plonk_polynomial_dfs_table = zk::snark::plonk_polynomial_dfs_table<FieldType>;
                using var = zk::snark::plonk_variable<
                    typename plonk_polynomial_dfs_table::column_type>;

                struct var_without_rotation {
                    std::size_t index;
                    var::column_type type;

                    auto operator<=>(var_without_rotation const &) const = default;
                };

                struct var_without_rotation_hash {
                    std::size_t operator()(const var_without_rotation &v) const {
                        auto v_hash = boost::hash_value(v.index);
                        boost::hash_combine(v_hash, v.type);
                        return v_hash;
                    }
                };

                struct variable_pair_hash {
                    std::size_t operator()(
                        const std::pair<var_without_rotation, std::size_t> &v) const {
                        auto v_hash = boost::hash_value(v.first.index);
                        boost::hash_combine(v_hash, v.first.type);
                        boost::hash_combine(v_hash, v.second);
                        return v_hash;
                    }
                };

                using pair_type = std::pair<var_without_rotation, std::size_t>;

                const plonk_polynomial_dfs_table &table;
                std::unordered_map<std::size_t, std::shared_ptr<domain_type>>
                    domain_cache;
                std::unordered_map<pair_type, std::shared_ptr<polynomial_type>,
                                   variable_pair_hash>
                    cache;
                std::unordered_map<var_without_rotation, std::shared_ptr<polynomial_type>,
                                   var_without_rotation_hash>
                    ifft_cache;
                std::unordered_map<var_without_rotation, std::int32_t,
                                   var_without_rotation_hash>
                    var_rotation;

                std::size_t column_size;
                std::shared_ptr<domain_type> domain;

                dfs_cache(const plonk_polynomial_dfs_table &table,
                          polynomial_type mask_assignment, polynomial_type lagrange_0)
                    : table(table),
                      column_size(mask_assignment.size()),
                      domain(get_domain(column_size)) {}

                dfs_cache(const dfs_cache &) = default;
                dfs_cache &operator=(const dfs_cache &) = default;

                void ensure_domain(std::size_t size) {
                    if (!domain_cache.contains(size)) {
                        domain_cache[size] = make_evaluation_domain<FieldType>(size);
                    }
                }

                std::shared_ptr<domain_type> get_domain(std::size_t size) {
                    auto it = domain_cache.find(size);
                    if (it != domain_cache.end()) {
                        return it->second;
                    }
                    auto new_domain = make_evaluation_domain<FieldType>(size);
                    domain_cache[size] = new_domain;
                    return new_domain;
                }

                template<typename VariableType>
                void ensure_cache(const std::set<VariableType> &variables,
                                  std::size_t size) {
                    if (column_size > size) {
                        throw std::invalid_argument(
                            "Column size is more than the requested "
                            "size");
                    }
                    ensure_domain(size);
                    std::vector<var_without_rotation> new_vars_ifft;
                    std::vector<std::int32_t> new_vars_ifft_rotation;
                    std::set<var_without_rotation> new_vars_ifft_set;
                    for (const auto &uncon_v : variables) {
                        auto v = get_var_without_rotation(uncon_v);

                        if (is_cached_ifft(v) || new_vars_ifft_set.contains(v)) {
                            continue;
                        }
                        new_vars_ifft.push_back(v);
                        new_vars_ifft_rotation.push_back(uncon_v.rotation);
                        new_vars_ifft_set.insert(v);
                        ifft_cache[v] = nullptr;
                        var_rotation[v] = uncon_v.rotation;
                    }

                    parallel_for(
                        0, new_vars_ifft.size(),
                        [&new_vars_ifft, &new_vars_ifft_rotation, this](std::size_t i) {
                            auto og_column = table.get_variable_value(
                                var(new_vars_ifft[i].index, new_vars_ifft_rotation[i],
                                    false, new_vars_ifft[i].type),
                                domain);
                            domain->inverse_fft(og_column.get_storage());
                            ifft_cache[new_vars_ifft[i]] =
                                std::make_shared<polynomial_type>(std::move(og_column));
                        },
                        ThreadPool::PoolLevel::HIGH);

                    std::vector<var_without_rotation> new_vars;
                    std::set<var_without_rotation> new_vars_set;
                    for (const auto &uncon_v : variables) {
                        auto v = get_var_without_rotation(uncon_v);
                        if (is_cached(v, size) || new_vars_set.contains(v)) {
                            continue;
                        }
                        new_vars.push_back(v);
                        new_vars_set.insert(v);
                        cache[pair_type(v, size)] = nullptr;
                    }

                    parallel_for(
                        0, new_vars.size(),
                        [&new_vars, size, this](std::size_t i) {
                            auto cached_result_copy = *ifft_cache[new_vars[i]];
                            cached_result_copy.get_storage().resize(size,
                                                                    value_type::zero());
                            get_domain(size)->fft(cached_result_copy.get_storage());
                            cache[std::make_pair(new_vars[i], size)] =
                                std::make_shared<polynomial_type>(
                                    std::move(cached_result_copy));
                        },
                        ThreadPool::PoolLevel::HIGH);
                }

                template<typename VariableType>
                var_without_rotation get_var_without_rotation(
                    const VariableType &uncon_v) {
                    if (uncon_v.index >= zk::snark::PLONK_MAX_SELECTOR_ID) {
                        throw std::runtime_error("dfs_cache: unsupported variable type");
                    }
                    return {uncon_v.index, typename var::column_type(uncon_v.type)};
                }

                bool is_cached_ifft(var_without_rotation v) {
                    return var_rotation.contains(v);
                }
                bool is_cached(var_without_rotation v, std::size_t size) {
                    const auto key = std::make_pair(v, size);
                    return cache.contains(key);
                }

                // we might have different types of variables, and this auto-converts them
                // to one type
                template<typename VariableType>
                std::shared_ptr<polynomial_type> get(const VariableType &uncon_v,
                                                     std::size_t size) {
                    auto v = get_var_without_rotation(uncon_v);
                    return get(v, uncon_v.rotation, size);
                }

                std::shared_ptr<polynomial_type> get(var_without_rotation v,
                                                     std::int32_t rotation,
                                                     std::size_t size) {
                    auto old_result_it = cache.find(std::make_pair(v, size));
                    if (old_result_it == cache.end()) {
                        throw std::logic_error("Should be precomputed");
                    }
                    auto cur_rotation = var_rotation[v];
                    if (cur_rotation == rotation) {
                        return old_result_it->second;
                    }
                    // means that we have already resized this column
                    // to the requested size need to just shift the
                    // cached result
                    auto new_rotation = rotation;
                    auto old_result = *old_result_it->second;
                    // note that scaling the shift value is performed
                    // by polynomial_shift
                    std::int32_t shift = new_rotation - cur_rotation;
                    return std::make_shared<polynomial_type>(
                        math::polynomial_shift(old_result, shift, column_size));
                }
            };
        }  // namespace math
    } // namespace crypto3
} // namespace nil

#endif // PARALLEL_CRYPTO3_MATH_POLYNOMIAL_DFS_CACHE_HPP
