//---------------------------------------------------------------------------//
// Copyright (c) 2017-2021 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef MARSHALLING_PROCESSING_ALIGNED_UNION_HPP
#define MARSHALLING_PROCESSING_ALIGNED_UNION_HPP

#include <cstddef>
#include <type_traits>

namespace nil {
    namespace marshalling {
        namespace processing {

            /// @cond SKIP_DOC
            template<typename TType, typename... TTypes>
            class aligned_union {                
                using other_storage_type = typename aligned_union<TTypes...>::type;
                using first_storage_type = typename aligned_union<TType>::type;
                using align_type = std::conditional_t<
                    alignof(first_storage_type) >= alignof(other_storage_type), 
                    first_storage_type, 
                    other_storage_type
                >;
                
            public:
                /// Type that has proper size and proper alignment to keep any of the
                /// specified types
                struct alignas(align_type) type { std::byte __data[sizeof(align_type)]; };
            };

            template<typename TType>
            class aligned_union<TType> {
            public:
                struct alignas(TType) type { std::byte __data[sizeof(TType)]; };
            };

            /// @endcond

        }    // namespace processing
    }    // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_PROCESSING_ALIGNED_UNION_HPP
