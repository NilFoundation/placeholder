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
            template<typename VariableType>
            struct variable_pair_hash {
                std::size_t operator()(const std::pair<VariableType, std::size_t> &v) const {
                    auto v_hash = std::hash<VariableType>()(v.first);
                    boost::hash_combine(v_hash, v.second);
                    return v_hash;
                }
            };

            template<typename FieldType>
            struct dfs_cache {
                using value_type = typename FieldType::value_type;
                using polynomial_type = polynomial_dfs<value_type>;
                using domain_type = evaluation_domain<FieldType>;
                using plonk_polynomial_dfs_table = zk::snark::plonk_polynomial_dfs_table<FieldType>;
                using var = zk::snark::plonk_variable<typename plonk_polynomial_dfs_table::column_type>;
                using pair_type = std::pair<var, std::size_t>;
                using pair_hash_type = variable_pair_hash<var>;

                static constexpr const std::array<int32_t, 15> possible_rotations = {
                    -7, -6, -5, -4, -3, -2, -1, 0, 1, 2, 3, 4, 5, 6, 7
                };

                const plonk_polynomial_dfs_table &table;
                std::unordered_map<std::size_t, std::shared_ptr<domain_type>> domain_cache;
                std::unordered_map<pair_type, std::shared_ptr<polynomial_type>, pair_hash_type> cache;
                std::unordered_map<var, std::shared_ptr<polynomial_type>> ifft_cache;
                std::unordered_set<pair_type, pair_hash_type> rotationless_vars;

                std::size_t column_size;

                dfs_cache(const plonk_polynomial_dfs_table &table,
                    polynomial_type mask_assignment,
                    polynomial_type lagrange_0
                ) : table(table), column_size(mask_assignment.size()) {
                    cache[std::make_pair(
                        var(zk::snark::PLONK_SPECIAL_SELECTOR_ALL_USABLE_ROWS_SELECTED, 0, false, var::column_type::selector),
                        column_size
                    )] = std::make_shared<polynomial_type>(mask_assignment);
                    cache[std::make_pair(
                        var(zk::snark::PLONK_SPECIAL_SELECTOR_ALL_NON_FIRST_USABLE_ROWS_SELECTED, 0, false, var::column_type::selector),
                        column_size
                    )] = std::make_shared<polynomial_type>(mask_assignment - lagrange_0);
                    cache[std::make_pair(
                        var(zk::snark::PLONK_SPECIAL_SELECTOR_ALL_ROWS_SELECTED, 0, false, var::column_type::selector),
                        column_size
                    )] = std::make_shared<polynomial_type>(polynomial_type(0, column_size, value_type::one()));
                    // pre-create the base domain
                    domain_cache[column_size] = make_evaluation_domain<FieldType>(column_size);
                }

                dfs_cache(const dfs_cache &) = default;
                dfs_cache &operator=(const dfs_cache &) = default;

                // we might have different types of variables, and this auto-converts them to one type
                template<typename VariableType>
                std::shared_ptr<polynomial_type> get(const VariableType &uncon_v, std::size_t size) {
                    var v;
                    if constexpr (std::is_same_v<VariableType, var>) {
                        v = var(uncon_v);
                    } else {
                        v = var(uncon_v.index, uncon_v.rotation, false, typename var::column_type(uncon_v.type));
                    }
                    v.relative = false;
                    const auto key = std::make_pair(v, size);
                    if (cache.find(key) != cache.end()) {
                        auto res = cache[key];
                        return res;
                    }
                    if (column_size > size) {
                        throw std::invalid_argument("Column size is more than the requested size");
                    }
                    // many different subcases in order to avoid unnecessary copying/computation
                    std::shared_ptr<domain_type> old_domain;
                    auto old_dom_it = domain_cache.find(column_size);
                    if (old_dom_it == domain_cache.end()) {
                        throw std::logic_error("OG Domain not found in cache");
                    }
                    old_domain = old_dom_it->second;
                    if (column_size == size) {
                        auto res = std::make_shared<polynomial_type>(table.get_variable_value(v, old_domain));
                        cache[key] = res;
                        return res;
                    }
                    auto var_without_rotation = var(v.index, 0, false, v.type);
                    auto rotationless_key = std::make_pair(var_without_rotation, size);
                    if (rotationless_vars.find(rotationless_key) != rotationless_vars.end()) {
                        // means that we have already resized this column to the requested size
                        // need to just shift the cached result
                        auto &cur_rotation = v.rotation;
                        int new_rotation = 0;
                        std::shared_ptr<polynomial_type> old_result = nullptr;
                        var tmp_v = var_without_rotation;
                        for (const auto &possible_rotation : possible_rotations) {
                            if (possible_rotation == cur_rotation) {
                                continue;
                            }
                            tmp_v.rotation = possible_rotation;
                            auto old_key = std::make_pair(tmp_v, size);
                            auto cache_it = cache.find(old_key);
                            if (cache_it != cache.end()) {
                                old_result = cache_it->second;
                                new_rotation = possible_rotation;
                                break;
                            }
                        }
                        if (old_result == nullptr) {
                            throw std::logic_error(
                                "It seems that max possible rotation got exceeded, please increase it possible_rotations."
                            );
                        }
                        // note that scaling the shift value is performed by polynomial_shift
                        int shift = cur_rotation - new_rotation;
                        auto new_res = std::make_shared<polynomial_type>(
                            math::polynomial_shift(*old_result, shift, column_size)
                        );
                        cache[key] = new_res;
                        return new_res;
                    }
                    rotationless_vars.insert(rotationless_key);
                    // resizing is necessary
                    std::shared_ptr<domain_type> new_domain;
                    auto new_dom_it = domain_cache.find(size);
                    if (new_dom_it == domain_cache.end()) [[unlikely]] {
                        domain_cache[size] = make_evaluation_domain<FieldType>(size);
                    }
                    new_domain = domain_cache[size];
                    auto ifft_cache_it = ifft_cache.find(v);
                    if (ifft_cache_it != ifft_cache.end()) {
                        // just have to run forward FFT
                        auto cached_result_copy = *ifft_cache_it->second;
                        cached_result_copy.get_storage().resize(size, value_type::zero());
                        new_domain->fft(cached_result_copy.get_storage());
                        auto res = std::make_shared<polynomial_type>(std::move(cached_result_copy));
                        cache[key] = res;
                        return res;
                    }
                    polynomial_type og_column;
                    if ((v.index == zk::snark::PLONK_SPECIAL_SELECTOR_ALL_USABLE_ROWS_SELECTED ||
                         v.index == zk::snark::PLONK_SPECIAL_SELECTOR_ALL_NON_FIRST_USABLE_ROWS_SELECTED ||
                         v.index == zk::snark::PLONK_SPECIAL_SELECTOR_ALL_ROWS_SELECTED) &&
                         v.type == var::column_type::selector)
                    {
                        auto column_size_key = std::make_pair(v, column_size);
                        auto special_it = cache.find(column_size_key);
                        if (special_it != cache.end()) {
                            og_column = *special_it->second;
                        } else {
                            // we have to rotate the column
                            auto special_rotationless_key = std::make_pair(var_without_rotation, column_size);
                            auto rotationless_it = cache.find(special_rotationless_key);
                            if (rotationless_it == cache.end()) {
                                throw std::logic_error("Special selector column not found in cache");
                            }
                            og_column = math::polynomial_shift(
                                *rotationless_it->second,
                                - v.rotation,
                                column_size
                            );
                            cache[column_size_key] = std::make_shared<polynomial_type>(og_column);
                        }
                    } else {
                        og_column = table.get_variable_value(v, old_domain);
                    }
                    old_domain->inverse_fft(og_column.get_storage());
                    ifft_cache[v] = std::make_shared<polynomial_type>(og_column);
                    new_domain->fft(og_column.get_storage());
                    auto res = std::make_shared<polynomial_type>(std::move(og_column));
                    cache[key] = res;
                    return res;
                }
            };
        } // namespace math
    } // namespace crypto3
} // namespace nil

#endif // PARALLEL_CRYPTO3_MATH_POLYNOMIAL_DFS_CACHE_HPP
