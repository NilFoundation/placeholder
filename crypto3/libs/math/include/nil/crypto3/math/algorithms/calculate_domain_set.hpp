//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_MATH_CALCULATE_DOMAIN_SET_HPP
#define CRYPTO3_MATH_CALCULATE_DOMAIN_SET_HPP

#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>

#include <nil/actor/core/thread_pool.hpp>
#include <nil/actor/core/parallelization_utils.hpp>

namespace nil {
    namespace crypto3 {
        namespace math {

            template<typename FieldType>
            std::vector<std::shared_ptr<evaluation_domain<FieldType>>>
                calculate_domain_set(const std::size_t max_domain_degree, const std::size_t set_size) {

                std::vector<std::shared_ptr<evaluation_domain<FieldType>>> domain_set(set_size);

                // make_evaluation_domain uses LOW level thread pool, so this function needs to use
                // ThreadPool::PoolLevel::HIGH.
                parallel_for(0, set_size, [&domain_set, max_domain_degree](std::size_t i){
                    const std::size_t domain_size = std::pow(2, max_domain_degree - i);
                    std::shared_ptr<evaluation_domain<FieldType>> domain =
                        make_evaluation_domain<FieldType>(domain_size);
                    domain_set[i] = domain;
                }, ThreadPool::PoolLevel::HIGH);

                return domain_set;
            }
        }    // namespace math
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MATH_CALCULATE_DOMAIN_SET_HPP
