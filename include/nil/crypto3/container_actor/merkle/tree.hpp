//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021-2022 Aleksei Moskvin <alalmoskvin@gmail.com>
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

#ifndef ACTOR_MERKLE_TREE_HPP
#define ACTOR_MERKLE_TREE_HPP

#include <vector>
#include <cmath>

#include <boost/config.hpp>

#include <nil/crypto3/detail/static_digest.hpp>
#include <nil/crypto3/detail/type_traits.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/actor/core/future.hh>
#include <nil/crypto3/container/merkle/node.hpp>
#include <nil/crypto3/container/merkle/tree.hpp>

#include <nil/actor/core/when_all.hh>

#include <nil/actor/core/alien.hh>

namespace nil {
    namespace actor {
        namespace containers {
            namespace detail {

                //                nil::actor::future<> f() {
                //                    return nil::actor::parallel_for_each(
                //                        boost::irange<unsigned>(0, nil::actor::smp::count),
                //                        [](unsigned c) { return nil::actor::smp::submit_to(c, service_loop); });
                //                }

                template<typename T, std::size_t Arity, typename LeafIterator>
                containers::detail::merkle_tree_impl<T, Arity> make_merkle_tree(LeafIterator first, LeafIterator last) {
                    typedef T node_type;
                    typedef typename node_type::hash_type hash_type;
                    typedef typename node_type::value_type value_type;

                    containers::detail::merkle_tree_impl<T, Arity> ret(std::distance(first, last));

                    ret.reserve(ret.complete_size());

                    while (first != last) {
                        ret.emplace_back(crypto3::hash<hash_type>(*first++));
                    }

                    //                    ret.resize(ret.complete_size());

                    std::size_t row_size = ret.leaves() / Arity;
                    typename containers::detail::merkle_tree_impl<T, Arity>::iterator it = ret.begin();

                    for (size_t row_number = 1; row_number < ret.row_count(); ++row_number, row_size /= Arity) {
                        std::vector<nil::actor::future<std::vector<typename hash_type::digest_type>>> fut;
                        std::size_t parallels = std::min((std::size_t)nil::actor::smp::count, row_size);
                        std::size_t node_per_shard = row_size / parallels;

                        for (auto c = 0; c < parallels; ++c) {
                            auto begin_row = node_per_shard * c;
                            auto end_row = std::min(node_per_shard * (c + 1), row_size);
                            auto it_c = it + node_per_shard * c * Arity;

                            fut.push_back(nil::actor::smp::submit_to(c, [begin_row, end_row, it_c] {
                                std::vector<typename hash_type::digest_type> res;
                                for (size_t i = 0; i < end_row - begin_row; ++i) {
                                    res.push_back(nil::crypto3::containers::detail::generate_hash<hash_type>(
                                        it_c + i * Arity, it_c + (i + 1) * Arity));
                                }
                                return nil::actor::make_ready_future<std::vector<typename hash_type::digest_type>>(res);
                            }));
                        }

                        it += Arity * row_size;

                        for (auto &i : fut) {
                            std::vector<typename hash_type::digest_type> v = i.get();
                            for (std::size_t j = 0; j < v.size(); ++j) {
                                ret.emplace_back(v[j]);
                                std::cout << v[j] << std::endl;
                            }
                        }
                    }
                    return ret;
                }
            }    // namespace detail

            template<typename T, std::size_t Arity, typename LeafIterator>
            nil::crypto3::containers::merkle_tree<T, Arity> make_merkle_tree(LeafIterator first, LeafIterator last) {
                return detail::make_merkle_tree<
                    typename std::conditional<nil::crypto3::detail::is_hash<T>::value,
                                              nil::crypto3::containers::detail::merkle_tree_node<T>, T>::type,
                    Arity>(first, last);
            }

        }    // namespace containers
    }        // namespace actor
}    // namespace nil

#endif    // ACTOR_MERKLE_TREE_HPP
