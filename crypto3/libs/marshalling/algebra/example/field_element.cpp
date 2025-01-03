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

#include <iostream>
#include <iomanip>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <nil/crypto3/algebra/curves/mnt4.hpp>

#include <nil/marshalling/algorithms/pack.hpp>
#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>
#include "nil/crypto3/algebra/fields/bls12/base_field.hpp"

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
    using g1_base_field = nil::crypto3::algebra::curves::mnt4<298>::g1_type<>::field_type;
    using g2_base_field = nil::crypto3::algebra::curves::mnt4<298>::g2_type<>::field_type;

    using be = nil::crypto3::marshalling::option::big_endian;
    using le = nil::crypto3::marshalling::option::little_endian;
    using unit_type = unsigned char;

    nil::crypto3::marshalling::status_type status;
    typename g1_base_field::value_type x1 { 0xDEADBEEF };
    std::vector<unit_type> cv_le = nil::crypto3::marshalling::pack<le>(x1, status);
    std::cout << "Marshalling x1: " << x1 << ": " << make_error_code(status) << std::endl;
    std::cout << "Little endian:" << std::endl;
    print_buffer(cv_le);
    std::cout << std::endl;

    std::vector<unit_type> cv_be = nil::crypto3::marshalling::pack<be>(x1, status);
    std::cout << "Marshalling x1: " << x1 << ": " << make_error_code(status) << std::endl;
    std::cout << "Big endian:" << std::endl;
    print_buffer(cv_be);
    std::cout << std::endl;

    typename g2_base_field::value_type x2 { 0xC001CAFE, 0x8badf00d };

    std::vector<unit_type> cv2_le = nil::crypto3::marshalling::pack<le>(x2, status);
    std::cout << "Marshalling x2: " << x2 << ": " << make_error_code(status) << std::endl;
    std::cout << "Little endian:" << std::endl;
    print_buffer(cv2_le);
    std::cout << std::endl;

    std::vector<unit_type> cv2_be = nil::crypto3::marshalling::pack<be>(x2, status);
    std::cout << "Marshalling x2: " << x2 << ": " << make_error_code(status) << std::endl;
    std::cout << "Big endian:" << std::endl;
    print_buffer(cv2_be);
    std::cout << std::endl;

    return 0;

}
