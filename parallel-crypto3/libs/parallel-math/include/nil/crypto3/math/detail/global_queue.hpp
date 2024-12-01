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

#include <sycl/sycl.hpp>

#pragma once

sycl::queue GLOBAL_QUEUE(sycl::gpu_selector{});

template<typename T>
using shared_usm_allocator = sycl::usm_allocator<T, sycl::usm::alloc::shared>;

template<typename T>
class global_usm_allocator {
public:
    using value_type = T;
    using propagate_on_container_copy_assignment = std::true_type;
    using propagate_on_container_move_assignment = std::true_type;
    using propagate_on_container_swap = std::true_type;

    static shared_usm_allocator<T>& get() {
        static shared_usm_allocator<T> instance(GLOBAL_QUEUE); // Assuming global queue
        return instance;
    }

    T* allocate(size_t n) const {
        return get().allocate(n);
    }

    void deallocate(T* p, size_t n) const {
        get().deallocate(p, n);
    }

    const bool operator==(const global_usm_allocator<T>&) const {
        return true;
    }

    const bool operator!=(const global_usm_allocator<T>&) const {
        return false;
    }
};
