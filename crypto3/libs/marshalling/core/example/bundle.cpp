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
// This example shows marshalling of `bundle` structure that contains array_list

#include <cstdint>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/algorithms/pack.hpp>
#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>

#include <cstdio>
#include <iostream>
#include <iomanip>
#include <tuple>


using namespace nil::crypto3::marshalling;

template<typename unit>
void print_buffer(std::vector<unit> const& v)
{
    for(size_t i = 0; i < v.size(); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (unsigned int)v[i] << " ";
        if ( i % 16 == 15 ) std::cout << std::endl;
    }
}


struct S {
    int x;
    std::vector<int> y;
};

std::ostream& operator<<(std::ostream& os, S const& s)
{
    os << std::dec;
    os << "S { " << std::endl;
    os << "    x = " << s.x << ";" << std::endl;
    os << "    y = " << s.y.size() << " [ ";
    for(auto const& v: s.y) {
        os << v << " ";
    }
    os << "];" << std::endl;
    os << "};" << std::endl;

    return os;
}

int main()
{
    using be = option::big_endian;
    using marshalling_type = field_type<be>;

    using S_marshalling_type = types::bundle<
        marshalling_type,
        std::tuple<
            types::integral<marshalling_type, int>,
            types::standard_array_list<
                marshalling_type,
                types::integral<marshalling_type, int>
            >
        >
    >;

    /* Fill marshalling type from struct S */
    auto fill_S = [](S const& s) {
        S_marshalling_type result;

        std::get<0>(result.value()).value() = s.x;
        for(auto const& v: s.y) {
            auto i = types::integral<marshalling_type, int>(v);
            std::get<1>(result.value()).value().push_back(i);
        }

        return result;
    };

    /* Make struct S from marshalled type */
    auto make_S = [](S_marshalling_type const& m) {
        S result {
            .x = std::get<0>(m.value()).value(),
            .y {},
        };

        for(auto const& v: std::get<1>(m.value()).value()) {
            result.y.push_back(v.value());
        }
        return result;
    };

    S s {
        .x = 10,
        .y {11,12,13,14,15,16,17,18},
    };

    std::cout << "Marshalling structure " << s;

    auto m = fill_S(s);
    nil::crypto3::marshalling::status_type status;
    std::vector<uint8_t> cv = pack(m, status);
    std::cout << "Status: " << make_error_code(status) << std::endl;

    std::cout << "Byte array: " << std::endl;
    print_buffer(cv);
    std::cout << std::endl;

    std::cout << "Recovering structure from byte array" << std::endl;
    auto m2 = pack(cv, status);
    std::cout << "Status: " << make_error_code(status) << std::endl;
    S s2 = make_S(m2);
    std::cout << "Recovered from byte array: " << s2;

    return 0;

}
