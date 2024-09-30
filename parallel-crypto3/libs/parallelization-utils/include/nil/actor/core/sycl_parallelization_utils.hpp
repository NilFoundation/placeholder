//---------------------------------------------------------------------------//
// Copyright (c) 2024 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#include <functional>
#include <hipsycl/sycl.hpp>

namespace nil {
    namespace crypto3 {
        template<class Function>
        void sycl_run_in_chunks(
            std::size_t elements_count,
            Function func
        ) {
            hipsycl::queue q;
            std::size_t max_compute_units = q.get_device().get_info<hipsycl::info::device::max_compute_units>();
            std::size_t workers_to_use =
                std::max(static_cast<std::size_t>(1), std::min(elements_count, max_compute_units));
            {
                q.submit([&](hipsycl::handler& cgh) {
                    cgh.parallel_for<class ParallelRunKernel>(
                            hipsycl::range<1>(workers_to_use), [=](hipsycl::id<1> idx) {
                        const std::size_t i = idx[0];
                        const std::size_t chunk_size = elements_count / workers_to_use;
                        const std::size_t remainder = elements_count % workers_to_use;
                        const std::size_t begin = i * chunk_size + hipsycl::min(i, remainder);
                        const std::size_t end = begin + chunk_size + (i < remainder ? 1 : 0);
                        func(begin, end);
                    });
                });
                // The buffer destructor ensures synchronization
            }
        }

        template<class Function>
        void sycl_parallel_for(
            std::size_t start,
            std::size_t end,
            Function func
        ) {
            hipsycl::queue q;
            {
                q.submit([&](hipsycl::handler& cgh) {
                    cgh.parallel_for<class ParallelForKernel>(
                            hipsycl::range<1>(end - start), [=](hipsycl::id<1> idx) {
                        func(start + idx[0]);
                    });
                });
                // The buffer destructor ensures synchronization
            }
        }
    }   // namespace crypto3
}   // namespace nil