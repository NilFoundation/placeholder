//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
// Copyright (c) 2025 Andrey Nefedov <ioxid@nil.foundation>
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

#ifndef CRYPTO3_MATH_POLYNOMIAL_STATIC_SIMD_VECTOR_HPP
#define CRYPTO3_MATH_POLYNOMIAL_STATIC_SIMD_VECTOR_HPP

#include <algorithm>

#include <boost/container/static_vector.hpp>
#include <boost/functional/hash.hpp>

#include <nil/crypto3/bench/scoped_profiler.hpp>

#include <nil/crypto3/math/polynomial/polynomial_dfs.hpp>

#include <nil/crypto3/multiprecision/detail/big_mod/modular_ops/babybear_simd.hpp>

namespace nil::crypto3::algebra::fields {
    struct babybear;
}

namespace nil::crypto3::math {
    template<typename FieldValueType, std::size_t Size>
    class static_simd_vector {
        using container_type = std::array<FieldValueType, Size>;

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

        static_simd_vector() : static_simd_vector(FieldValueType::zero()) {}

        static_simd_vector(const value_type& x) { val.fill(x); }

        static_simd_vector(std::initializer_list<value_type> il) : val(il) {}

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

        void swap(static_simd_vector& other) noexcept { val.swap(other.val); }

        bool is_zero() const {
            for (const auto& v : val) {
                if (v != FieldValueType::zero()) return false;
            }
            return true;
        }

        bool is_one() const {
            for (const auto& v : val) {
                if (v != FieldValueType::one()) return false;
            }
            return true;
        }

        inline static static_simd_vector zero() { return static_simd_vector(); }

        inline static static_simd_vector one() {
            return static_simd_vector(value_type::one());
        }

        template<std::size_t VSize,
                 std::array<FieldValueType, VSize> op(std::array<FieldValueType, VSize>,
                                                      std::array<FieldValueType, VSize>)>
        static void vectorize(const static_simd_vector& lhs,
                              const static_simd_vector& rhs, static_simd_vector& result) {
            static_assert(Size % VSize == 0);
            for (std::size_t i = 0; i < Size / VSize; ++i) {
                std::array<FieldValueType, VSize> lhs_v, rhs_v;
                for (std::size_t j = 0; j < VSize; ++j) {
                    lhs_v[j] = lhs[i * VSize + j];
                    rhs_v[j] = rhs[i * VSize + j];
                }
                auto r = op(lhs_v, rhs_v);
                for (std::size_t j = 0; j < VSize; ++j) {
                    result[i * VSize + j] = r[j];
                }
            }
        }

        static_simd_vector operator+(const static_simd_vector& other) const {
            static_simd_vector result;
            if constexpr (std::is_same_v<typename FieldValueType::field_type,
                                         algebra::fields::babybear>) {
                vectorize<8, nil::crypto3::multiprecision::detail::babybear::
                                 babybear_add8<FieldValueType>>(*this, other, result);
                return result;
            }
            for (std::size_t i = 0; i < Size; ++i) {
                result[i] = (*this)[i] + other[i];
            }
            return result;
        }

        static_simd_vector& operator+=(const static_simd_vector& other) {
            if constexpr (std::is_same_v<typename FieldValueType::field_type,
                                         algebra::fields::babybear>) {
                vectorize<8, nil::crypto3::multiprecision::detail::babybear::
                                 babybear_add8<FieldValueType>>(*this, other, *this);
                return *this;
            }
            for (std::size_t i = 0; i < Size; ++i) {
                (*this)[i] += other[i];
            }
            return *this;
        }

        static_simd_vector& operator+=(const FieldValueType& c) {
            for (std::size_t i = 0; i < Size; ++i) {
                (*this)[i] += c;
            }
            return *this;
        }

        static_simd_vector operator-() const {
            static_simd_vector result;
            for (std::size_t i = 0; i < Size; ++i) {
                result[i] = -(*this)[i];
            }
            return result;
        }

        static_simd_vector operator-(const static_simd_vector& other) const {
            static_simd_vector result;
            for (std::size_t i = 0; i < Size; ++i) {
                result[i] = (*this)[i] - other[i];
            }
            return result;
        }

        static_simd_vector& operator-=(const static_simd_vector& other) {
            for (std::size_t i = 0; i < Size; ++i) {
                (*this)[i] -= other[i];
            }
            return *this;
        }

        static_simd_vector& operator-=(const FieldValueType& c) {
            for (std::size_t i = 0; i < Size; ++i) {
                (*this)[i] -= c;
            }
            return *this;
        }

        static_simd_vector operator*(const static_simd_vector& other) const {
            static_simd_vector result;
            if constexpr (std::is_same_v<typename FieldValueType::field_type,
                                         algebra::fields::babybear>) {
                vectorize<8, nil::crypto3::multiprecision::detail::babybear::
                                 babybear_mul8<FieldValueType>>(*this, other, result);
                return result;
            }
            for (std::size_t i = 0; i < Size; ++i) {
                result[i] = (*this)[i] * other[i];
            }
            return result;
        }

        static_simd_vector& operator*=(const static_simd_vector& other) {
            if constexpr (std::is_same_v<typename FieldValueType::field_type,
                                         algebra::fields::babybear>) {
                vectorize<8, nil::crypto3::multiprecision::detail::babybear::
                                 babybear_mul8<FieldValueType>>(*this, other, *this);
                return *this;
            }
            for (std::size_t i = 0; i < Size; ++i) {
                (*this)[i] *= other[i];
            }
            return *this;
        }

        static_simd_vector& operator*=(const FieldValueType& alpha) {
            for (std::size_t i = 0; i < Size; ++i) {
                (*this)[i] *= alpha;
            }
            return *this;
        }

        static_simd_vector pow(size_t power) const {
            if (power == 1) {
                return *this;
            }

            static_simd_vector result;

            for (std::size_t i = 0; i < result.size(); ++i) {
                result[i] = (*this)[i].pow(power);
            }

            return result;
        }

        constexpr auto operator<=>(const static_simd_vector& other) const {
            return std::lexicographical_compare_three_way(this->begin(), this->end(),
                                                          other.begin(), other.end());
        }

        constexpr bool operator==(const static_simd_vector& rhs) const {
            return (*this <=> rhs) == 0;
        }
    };

    template<std::size_t Size>
    std::size_t count_chunks(std::size_t size) {
        return (size + Size - 1) / Size;
    }

    template<std::size_t Size, typename FieldValueType>
    static_simd_vector<FieldValueType, Size> get_chunk(
        const polynomial_dfs<FieldValueType>& poly, std::size_t offset,
        std::size_t number) {

        // If we have a constant value, our polynomial will frequently have size = 1, but we still
        // must return the chunk value.
        if (poly.degree() == 0) {
            return static_simd_vector<FieldValueType, Size>(poly[0]);
        }
        static_simd_vector<FieldValueType, Size> result;
        for (std::size_t i = 0; i < Size; ++i) {
            if (offset + number * Size + i >= poly.size()) {
                break;
            }
            result[i] = poly[offset + number * Size + i];
        }
        return result;
    }

    template<std::size_t Size, typename FieldValueType>
    void set_chunk(polynomial_dfs<FieldValueType>& poly, std::size_t offset,
                   std::size_t number,
                   const static_simd_vector<FieldValueType, Size>& chunk) {
        for (std::size_t i = 0; i < Size; ++i) {
            if (offset + number * Size + i >= poly.size()) {
                break;
            }
            poly[offset + number * Size + i] = chunk[i];
        }
    }

    // Used in the unit tests, so we can use BOOST_CHECK_EQUALS and while debugging.
    template<std::size_t Size, typename FieldValueType>
    std::ostream& operator<<(std::ostream& os,const static_simd_vector<FieldValueType, Size>& chunk) {
        os << "[";
        for (std::size_t i = 0; i < Size; ++i) {
            os << std::hex << std::showbase;
            os << chunk[i];
            if (i != Size - 1) {
                os << ", ";
            }
        }
        os << "]" << std::dec;
        return os;
    }

}  // namespace nil::crypto3::math

// As our operator== returns false for vectors with different sizes, the same will happen here,
// resized vector will have a different hash from the initial one.
template<typename FieldValueType, std::size_t Size>
struct std::hash<nil::crypto3::math::static_simd_vector<FieldValueType, Size>> {
    std::hash<FieldValueType> value_hasher;

    std::size_t operator()(
        const nil::crypto3::math::static_simd_vector<FieldValueType, Size>& v) const {
        std::size_t result = 0;
        for (const auto& val : v) {
            boost::hash_combine(result, value_hasher(val));
        }
        return result;
    }
};

#endif
