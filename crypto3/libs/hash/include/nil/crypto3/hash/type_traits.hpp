//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_HASH_TYPE_TRAITS_HPP
#define CRYPTO3_HASH_TYPE_TRAITS_HPP

#include <type_traits>

#include <nil/crypto3/hash/detail/poseidon/poseidon_sponge.hpp>
#include <nil/crypto3/hash/detail/sponge_construction.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {

            template<typename PolicyType>
            struct poseidon;

            template<typename Field, typename Hash, typename Params>
            struct h2f;

            template<typename Group, typename Hash, typename Params>
            struct h2c;

            template<typename Hash>
            struct is_h2f : std::integral_constant<bool, false> { };

            template<typename Field, typename Hash, typename Params>
            struct is_h2f<h2f<Field, Hash, Params>> : std::integral_constant<bool, true> { };

            template<typename Hash>
            struct is_h2c : std::integral_constant<bool, false> { };

            template<typename Group, typename Hash, typename Params>
            struct is_h2c<h2c<Group, Hash, Params>> : std::integral_constant<bool, true> { };

            // TODO: change this to more generic type trait to check for all sponge based hashes.
            template<typename HashType, typename Enable = void>
            struct is_poseidon {
            public:
                static const bool value = false;
            };

            template<typename HashType>
            struct is_poseidon<HashType, typename std::enable_if_t<std::is_same<nil::crypto3::hashes::poseidon<typename HashType::policy_type>, HashType>::value>> {
            public:
                static const bool value = true;
                typedef HashType type;
            };

            template <template <typename...> class PrimaryTemplate, typename T>
            struct is_specialization_of : std::false_type {};

            template <template <typename...> class PrimaryTemplate, typename... Args>
            struct is_specialization_of<PrimaryTemplate, PrimaryTemplate<Args...>> : std::true_type {};

            template<typename HashType, typename = void>
            struct uses_sponge_construction {
                static const bool value = false;
            };

            template<typename HashType>
            struct uses_sponge_construction<
                HashType,
                std::enable_if_t<
                    is_specialization_of<sponge_construction, typename HashType::construction::type>::value ||
                    is_specialization_of<algebraic_sponge_construction, typename HashType::construction::type>::value ||
                    is_specialization_of<nil::crypto3::hashes::detail::poseidon_sponge_construction_custom, typename HashType::construction::type>::value
                >
            > {
                static const bool value = true;
                typedef HashType type;
            };

        }    // namespace hashes
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_TYPE_TRAITS_HPP
