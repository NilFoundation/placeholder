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
// This example demonstrates usage of multiprecision integrals

#include <iostream>
#include <iomanip>

#include <nil/crypto3/multiprecision/integer.hpp>
#include <nil/crypto3/multiprecision/literals.hpp>

int main() {
    nil::crypto3::multiprecision::big_uint<128> x = 0x01, y = 0x01;
    nil::crypto3::multiprecision::big_uint<128> f;
    size_t N = 180;

    std::cout << N << " Fibonacci numbers:" << std::endl;
    std::cout << std::setw(5) << 0 << ": " << x << std::endl;
    std::cout << std::setw(5) << 1 << ": " << y << std::endl;

    for(size_t i = 2; i < N; ++i) {
        f = x + y;
        std::cout << std::setw(5) << i << ": " << f << std::endl;
        x = y;
        y = f;
    }

    N = 30;
    std::cout << N << " Factorials:" << std::endl;
    x = 1; f = 1;
    for(size_t i = 1; i <= N; ++i) {
        f *= x;
        x += 1;
        std::cout << std::setw(5) << i << ": " << f << std::endl;
    }
    return 0;
}
