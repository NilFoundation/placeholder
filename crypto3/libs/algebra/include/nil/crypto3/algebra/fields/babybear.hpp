//---------------------------------------------------------------------------//
// Copyright (c) 2025 Andrey Nefedov <ioxid@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_FIELDS_BABYBEAR_HPP
#define CRYPTO3_ALGEBRA_FIELDS_BABYBEAR_HPP

#include <cstddef>

#include <nil/crypto3/multiprecision/big_mod.hpp>
#include <nil/crypto3/multiprecision/big_uint.hpp>
#include <nil/crypto3/multiprecision/literals.hpp>

#include <nil/crypto3/algebra/fields/detail/element/fp.hpp>

#include <nil/crypto3/algebra/fields/field.hpp>
#include <nil/crypto3/algebra/fields/params.hpp>

namespace nil::crypto3::algebra::fields {
    /**
     * @brief A struct representing a Baby Bear field
     */
    class babybear : public field<31> {
      public:
        using policy_type = field<31>;

        constexpr static std::size_t value_bits = modulus_bits;
        constexpr static std::size_t arity = 1;

        using integral_type = policy_type::integral_type;

        // 2^31 - 2^27 + 1
        constexpr static integral_type modulus = 0x78000001_big_uint31;
        constexpr static integral_type group_order_minus_one_half = (modulus - 1u) / 2;

        using modular_type = nil::crypto3::multiprecision::auto_big_mod<modulus>;
        using value_type = detail::element_fp<params<babybear>>;
    };

    class babybear_montgomery_big_mod : public babybear {
      public:
        using modular_type = nil::crypto3::multiprecision::montgomery_big_mod<modulus>;
        using value_type = detail::element_fp<params<babybear_montgomery_big_mod>>;
    };

    class babybear_simple_31_bit : public babybear {
      public:
        using modular_type = nil::crypto3::multiprecision::big_mod_impl<nil::crypto3::multiprecision::detail::modular_ops_storage_ct<multiprecision::babybear_modulus, nil::crypto3::multiprecision::detail::simple_31_bit_modular_ops>>;
        using value_type = detail::element_fp<params<babybear_simple_31_bit>>;
    };
}  // namespace nil::crypto3::algebra::fields

#endif  // CRYPTO3_ALGEBRA_FIELDS_BABYBEAR_HPP
