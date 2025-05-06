//---------------------------------------------------------------------------//
// Copyright (c) 2025 Andrey Nefedov <ioxid@nil.foundation>
// Copyright (c) 2025 Martun Karapetyan <martun@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:`
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

#ifndef PARALLEL_CRYPTO3_MATH_POLYNOMIAL_FIELD_ELEMENT_VECTOR_HPP
#define PARALLEL_CRYPTO3_MATH_POLYNOMIAL_FIELD_ELEMENT_VECTOR_HPP

#ifdef CRYPTO3_MATH_POLYNOMIAL_DYNAMIC_SIMD_VECTOR_HPP
#error "You're mixing parallel and non-parallel crypto3 versions"
#endif

#include <vector>
#include <algorithm>
#include <stdexcept>

#include <boost/container/static_vector.hpp>
#include <boost/functional/hash.hpp>

#include <nil/crypto3/bench/scoped_profiler.hpp>

namespace nil::crypto3::math {

    // This is a wrapper over std::vector of field elements with operators+-*.
    // Even though this is a parallelized math library, do NOT parallelize functions of this class.
    // Usually it's size is <100.
    template<typename FieldValueType>
    class field_element_vector {
        using container_type = std::vector<FieldValueType>;

        container_type val;

      public:
        typedef typename container_type::value_type value_type;
        typedef typename container_type::reference reference;
        typedef typename container_type::const_reference const_reference;
        typedef typename container_type::size_type size_type;
        typedef typename container_type::difference_type difference_type;
        typedef typename container_type::pointer pointer;
        typedef typename container_type::const_pointer const_pointer;
        typedef typename container_type::iterator iterator;
        typedef typename container_type::const_iterator const_iterator;
        typedef typename container_type::reverse_iterator reverse_iterator;
        typedef typename container_type::const_reverse_iterator const_reverse_iterator;

        field_element_vector() = default; 

        field_element_vector(std::size_t N) : val(N, value_type::zero()) {}

        field_element_vector(std::size_t N, const value_type& x) : val(N, x) {}

        field_element_vector(std::initializer_list<value_type> il) : val(il) {}

        container_type& get_storage() { return val; }
        const container_type& get_storage() const { return val; }

        iterator begin() noexcept { return val.begin(); }
        const_iterator begin() const noexcept { return val.begin(); }
        iterator end() noexcept { return val.end(); }
        const_iterator end() const noexcept { return val.end(); }

        reverse_iterator rbegin() noexcept { return val.rbegin(); }

        const_reverse_iterator rbegin() const noexcept { return val.rbegin(); }

        reverse_iterator rend() noexcept { return reverse_iterator(begin()); }

        const_reverse_iterator rend() const noexcept {
            return const_reverse_iterator(begin());
        }

        const_iterator cbegin() const noexcept { return begin(); }

        const_iterator cend() const noexcept { return end(); }

        const_reverse_iterator crbegin() const noexcept { return rbegin(); }

        const_reverse_iterator crend() const noexcept { return rend(); }

        size_type size() const noexcept { return val.size(); }

        size_type capacity() const noexcept { return val.capacity(); }
        bool empty() const noexcept { return val.empty(); }
        size_type max_size() const noexcept { return val.max_size(); }

        reference operator[](size_type _n) noexcept { return val[_n]; }
        const_reference operator[](size_type _n) const noexcept { return val[_n]; }
        reference at(size_type _n) { return val.at(_n); }
        const_reference at(size_type _n) const { return val.at(_n); }

        reference front() noexcept { return val.front(); }
        const_reference front() const noexcept { return val.front(); }
        reference back() noexcept { return val.back(); }
        const_reference back() const noexcept { return val.back(); }

        value_type* data() noexcept { return val.data(); }

        const value_type* data() const noexcept { return val.data(); }

        void clear() noexcept { val.clear(); }
        void resize(size_type _sz) { val.resize(_sz); }

        void swap(field_element_vector& other) noexcept { val.swap(other.val); }

        field_element_vector operator+(const field_element_vector& other) const {
            field_element_vector result = *this;
            result += other;
            return result;
        }

        field_element_vector& operator+=(const field_element_vector& other) {
            if (this->size() < other.size()) {
                this->resize(other.size());
            }
            for (size_t i = 0; i < other.size(); ++i) {
                this->val[i] += other[i];
            }
            return *this;
        }
        field_element_vector& operator+=(const FieldValueType& c) {
            for (auto& v: val) {
                v += c;
            }
            return *this;
        }

        field_element_vector operator-() const {
            field_element_vector result(this->size());
            std::transform(this->begin(), this->end(), result.begin(), std::negate<FieldValueType>());
            return result;
        }

        field_element_vector operator-(const field_element_vector& other) const {
            field_element_vector result = *this;
            result -= other;
            return result;
        }

        field_element_vector& operator-=(const field_element_vector& other) {
            if (this->size() < other.size()) {
                this->resize(other.size());
            }
            for (size_t i = 0; i < other.size(); ++i) {
                this->val[i] -= other[i];
            }
            return *this;
        }

        field_element_vector& operator-=(const FieldValueType& c) {
            for (auto& v: val) {
                v -= c;
            }
            return *this;
        }
        field_element_vector operator*(const field_element_vector& other) const {
            field_element_vector result = *this;
            result *= other;
            return result;
        }

        field_element_vector& operator*=(const field_element_vector& other) {
            // It doesn't matter which one is longer, we assume the other one has zeros at the missing points.
            if (this->size() != other.size()) {
                this->resize(other.size());
            }
            for (size_t i = 0; i < other.size(); ++i) {
                this->val[i] *= other[i];
            }
            return *this;
        }

        field_element_vector& operator*=(const FieldValueType& c) {
            for (auto& v: val) {
                v *= c;
            }
            return *this;
        }

        field_element_vector pow(size_t power) const {
            if (power == 1) {
                return *this;
            }

            field_element_vector result;

            for (std::size_t i = 0; i < this->size(); ++i) {
                result[i] = (*this)[i].pow(power);
            }

            return result;
        }

        constexpr auto operator<=>(const field_element_vector& other) const {
            return std::lexicographical_compare_three_way(this->begin(), this->end(),
                                                          other.begin(), other.end());
        }

        constexpr bool operator==(const field_element_vector& rhs) const {
            return (*this <=> rhs) == 0;
        }
    };

    // Used in the unit tests, so we can use BOOST_CHECK_EQUALS and while debugging.
    template<typename FieldValueType>
    std::ostream& operator<<(std::ostream& os,const field_element_vector<FieldValueType>& chunk) {
        os << "[";
        for (std::size_t i = 0; i < chunk.size(); ++i) {
            os << std::hex << std::showbase;
            os << chunk[i];
            if (i != chunk.size() - 1) {
                os << ", "; 
            }
        }
        os << "]" << std::dec;
        return os;
    }

}  // namespace nil::crypto3::math

// As our operator== returns false for vectors with different sizes, the same will happen here,
// resized vector will have a different hash from the initial one.
template<typename FieldValueType>
struct std::hash<nil::crypto3::math::field_element_vector<FieldValueType>> {
    std::hash<FieldValueType> value_hasher;

    std::size_t operator()(
        const nil::crypto3::math::field_element_vector<FieldValueType>& v) const {
        std::size_t result = 0;
        for (const auto& val : v) {
            boost::hash_combine(result, value_hasher(val));
        }
        return result;
    }
};

#endif
