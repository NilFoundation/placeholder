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

#ifndef CRYPTO3_ALGEBRA_FIELDS_FPN_EXTENSION_HPP
#define CRYPTO3_ALGEBRA_FIELDS_FPN_EXTENSION_HPP

#include <nil/crypto3/algebra/fields/detail/element/fpn.hpp>
#include <nil/crypto3/algebra/fields/params.hpp>

namespace nil::crypto3::algebra::fields {
    template<detail::BinomialFieldExtensionParams Params>
    class fpn {
      public:
        using base_field_type = Params::base_field_type;

        constexpr static const std::size_t modulus_bits = base_field_type::modulus_bits;
        using integral_type = typename base_field_type::integral_type;

        constexpr static const std::size_t number_bits = base_field_type::number_bits;
        using modular_type = typename base_field_type::modular_type;

        constexpr static const integral_type modulus = base_field_type::modulus;

        using value_type = typename detail::element_fpn<Params>;

        constexpr static const std::size_t arity = Params::dimension;
        constexpr static const std::size_t value_bits = arity * modulus_bits;
    };
}  // namespace nil::crypto3::algebra::fields

#endif  // CRYPTO3_ALGEBRA_FIELDS_FPN_EXTENSION_HPP
