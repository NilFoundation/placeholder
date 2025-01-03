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
// This example shows the marshalling of curve elements

#include <iostream>
#include <iomanip>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/curves/detail/mnt4/g1.hpp>

#include <nil/crypto3/marshalling/algebra/inference.hpp>
#include <nil/crypto3/marshalling/algebra/types/curve_element.hpp>
#include <nil/crypto3/marshalling/algebra/processing/curve_element.hpp>
#include <nil/crypto3/marshalling/algebra/processing/mnt4.hpp>
#include <nil/marshalling/algorithms/pack.hpp>

template<typename unit>
void print_buffer(std::vector<unit> const& v)
{
    for(size_t i = 0; i < v.size(); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (unsigned int)v[i] << " ";
        if ( i % 16 == 15 ) std::cout << std::endl;
    }
}

int main()
{
    using g1 = nil::crypto3::algebra::curves::mnt4<298>::g1_type<>;
    using g2 = nil::crypto3::algebra::curves::mnt4<298>::g2_type<>;

    using be = nil::crypto3::marshalling::option::big_endian;
    using unit_type = unsigned char;

    nil::crypto3::marshalling::status_type status;
    auto G1 = g1::value_type::one();

    std::vector<unit_type> cv_be = nil::crypto3::marshalling::pack<be>(G1, status);
    std::cout << "Marshalling G1: " << G1 << ": " << make_error_code(status) << std::endl;
    std::cout << "Big endian:" << std::endl;
    print_buffer(cv_be);
    std::cout << std::endl;
    
    auto G2 = g2::value_type::one();

    std::vector<unit_type> cv2_be = nil::crypto3::marshalling::pack<be>(G2, status);
    std::cout << "Marshalling G2: " << G2 << ": " << make_error_code(status) << std::endl;
    std::cout << "Big endian:" << std::endl;
    print_buffer(cv2_be);
    std::cout << std::endl;
    
    return 0;

}
