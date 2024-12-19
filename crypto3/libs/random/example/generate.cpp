//---------------------------------------------------------------------------//
// Copyright (c) 2024 Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
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
// This example demonstrates usage of random engines to generate algebraic
// structures: field elements and elliptic curve points

#include <nil/crypto3/algebra/curves/mnt4.hpp>

#include <nil/crypto3/random/algebraic_engine.hpp>

int main() {
    using curve_type = typename ::nil::crypto3::algebra::curves::mnt4<298>;
    using scalar_type = typename curve_type::scalar_field_type;

    using scalar_generator_type = nil::crypto3::random::algebraic_engine<scalar_type>;
    scalar_generator_type scalar_generator;

    std::cout << "Some random elements from scalar group:" << std::endl;
    std::cout << scalar_generator() << std::endl;
    std::cout << scalar_generator() << std::endl;
    std::cout << scalar_generator() << std::endl;

    using g2_group = typename curve_type::template g2_type<>;
    using g2_generator_type = nil::crypto3::random::algebraic_engine<g2_group>;
    g2_generator_type g2_generator;

    std::cout << "Some random elements from G2 group:" << std::endl;
    std::cout << g2_generator() << std::endl;
    std::cout << g2_generator() << std::endl;
    std::cout << g2_generator() << std::endl;

    return 0;
}
