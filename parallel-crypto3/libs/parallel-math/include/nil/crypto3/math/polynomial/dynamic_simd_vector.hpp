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

#ifndef PARALLEL_CRYPTO3_MATH_POLYNOMIAL_DYNAMIC_SIMD_VECTOR_HPP
#define PARALLEL_CRYPTO3_MATH_POLYNOMIAL_DYNAMIC_SIMD_VECTOR_HPP

#ifdef CRYPTO3_MATH_POLYNOMIAL_DYNAMIC_SIMD_VECTOR_HPP
#error "You're mixing parallel and non-parallel crypto3 versions"
#endif

#include <vector>
#include <algorithm>
#include <stdexcept>

#include <boost/functional/hash.hpp>

#include <nil/crypto3/bench/scoped_profiler.hpp>

namespace nil::crypto3::math {
    template<typename FieldValueType, typename Allocator = std::allocator<FieldValueType>>
    class dynamic_simd_vector {
        typedef std::vector<FieldValueType, Allocator> container_type;

        container_type val;

      public:
        typedef typename container_type::value_type value_type;
        typedef typename container_type::allocator_type allocator_type;
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

        dynamic_simd_vector() : val(1, FieldValueType::zero()) {}

        explicit dynamic_simd_vector(size_type n) : val(n, FieldValueType::zero()) {}

        explicit dynamic_simd_vector(size_type n, const allocator_type& a)
            : val(n, FieldValueType::zero(), a) {}

        dynamic_simd_vector(size_type n, const value_type& x) : val(n, x) {}

        dynamic_simd_vector(size_type n, const value_type& x, const allocator_type& a)
            : val(n, x, a) {}

        template<typename InputIterator>
        dynamic_simd_vector(InputIterator first, InputIterator last) : val(first, last) {}

        template<typename InputIterator>
        dynamic_simd_vector(InputIterator first, InputIterator last, const allocator_type& a)
            : val(first, last, a) {}

        dynamic_simd_vector(const dynamic_simd_vector& x, const allocator_type& a) : val(x.val, a) {}

        dynamic_simd_vector(std::initializer_list<value_type> il) : val(il) {}

        dynamic_simd_vector(std::initializer_list<value_type> il, const allocator_type& a)
            : val(il, a) {}

        // NOLINTNEXTLINE
        dynamic_simd_vector(dynamic_simd_vector&& x, const allocator_type& a) : val(std::move(x.val), a) {}

        bool operator==(const dynamic_simd_vector& rhs) const { return val == rhs.val; }
        bool operator!=(const dynamic_simd_vector& rhs) const { return !(rhs == *this); }

        allocator_type get_allocator() const noexcept {
            return this->val.__alloc();
        }

        container_type& get_storage() { return val; }

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
        void reserve(size_type _n) { return val.reserve(_n); }
        void shrink_to_fit() noexcept { return val.shrink_to_fit(); }

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

        void push_back(const_reference _x) { val.push_back(_x); }

        void push_back(value_type&& _x) { val.emplace_back(std::move(_x)); }

        template<class... Args>
        reference emplace_back(Args&&... _args) {
            return val.template emplace_back<>(std::forward<Args...>(_args)...);
        }

        void pop_back() { val.pop_back(); }

        iterator insert(const_iterator _position, const_reference _x) {
            return val.insert(_position, _x);
        }

        iterator insert(const_iterator _position, value_type&& _x) {
            return val.insert(_position, std::move(_x));
        }
        template<class... Args>
        iterator emplace(const_iterator _position, Args&&... _args) {
            return val.template emplace<>(_position, std::forward<Args...>(_args)...);
        }

        iterator insert(const_iterator _position, size_type _n, const_reference _x) {
            return val.insert(_position, _n, _x);
        }

        template<class InputIterator>
        iterator insert(const_iterator _position, InputIterator _first,
                        InputIterator _last) {
            return val.insert(_position, _first, _last);
        }

        iterator insert(const_iterator _position, std::initializer_list<value_type> _il) {
            return insert(_position, _il.begin(), _il.end());
        }

        iterator erase(const_iterator _position) { return val.erase(_position); }

        iterator erase(const_iterator _first, const_iterator _last) {
            return val.erase(_first, _last);
        }

        void clear() noexcept { val.clear(); }

        void swap(dynamic_simd_vector& other) noexcept { val.swap(other.val); }

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

        inline static dynamic_simd_vector zero() { return dynamic_simd_vector(); }

        inline static dynamic_simd_vector one() {
            return dynamic_simd_vector(size_type(1), value_type::one());
        }

        bool is_single_value() const { return size() <= 1; }

        FieldValueType as_single_value() const {
            if (!is_single_value()) {
                throw std::runtime_error("can get one value only when vector size is <= 1");
            }
            if (size() == 1) {
                return val[0];
            }
            return FieldValueType::zero();
        }

      private:
        void ensure_size(std::size_t size) {
            if (size == 0) {
                throw std::logic_error("can't resize to 0");
            }
            if (this->size() == size) {
                return;
            }
            if (!is_single_value()) {
                throw std::runtime_error("can resize only when vector size is <= 1");
            }
            PROFILE_SCOPE("dynamic_simd_vector resize, size: " + std::to_string(size));
            auto c = as_single_value();
            val.resize(size);
            for (std::size_t i = 0; i < size; ++i) {
                val[i] = c;
            }
        }

      public:
        dynamic_simd_vector operator+(const dynamic_simd_vector& other) const {
            dynamic_simd_vector result = *this;
            result += other;
            return result;
        }

        dynamic_simd_vector& operator+=(const dynamic_simd_vector& other) {
            if (other.is_single_value()) {
                *this += other.as_single_value();
                return *this;
            }
            ensure_size(other.size());
            PROFILE_SCOPE("dynamic_simd_vector += other, size: " + std::to_string(this->size()));
            std::transform(other.begin(), other.end(), this->begin(), this->begin(),
                           std::plus<FieldValueType>());
            return *this;
        }

        dynamic_simd_vector& operator+=(const FieldValueType& c) {
            PROFILE_SCOPE("dynamic_simd_vector += c, size: " + std::to_string(this->size()));
            for (auto it = this->begin(); it != this->end(); it++) *it += c;
            return *this;
        }

        dynamic_simd_vector operator-() const {
            dynamic_simd_vector result = *this;
            PROFILE_SCOPE("dynamic_simd_vector negate, size: " + std::to_string(this->size()));
            std::transform(this->begin(), this->end(), result.begin(),
                           std::negate<FieldValueType>());
            return result;
        }

        dynamic_simd_vector operator-(const dynamic_simd_vector& other) const {
            dynamic_simd_vector result = *this;
            result -= other;
            return result;
        }

        dynamic_simd_vector& operator-=(const dynamic_simd_vector& other) {
            if (other.is_single_value()) {
                *this -= other.as_single_value();
                return *this;
            }
            ensure_size(other.size());
            PROFILE_SCOPE("dynamic_simd_vector -= other, size: " + std::to_string(this->size()));
            std::transform(this->begin(), this->end(), other.begin(), this->begin(),
                           std::minus<FieldValueType>());
            return *this;
        }

        dynamic_simd_vector& operator-=(const FieldValueType& c) {
            PROFILE_SCOPE("dynamic_simd_vector -= c, size: " + std::to_string(this->size()));
            for (auto it = this->begin(); it != this->end(); it++) *it -= c;
            return *this;
        }

        dynamic_simd_vector operator*(const dynamic_simd_vector& other) const {
            dynamic_simd_vector result = *this;
            result *= other;
            return result;
        }

        dynamic_simd_vector& operator*=(const dynamic_simd_vector& other) {
            if (other.is_single_value()) {
                *this *= other.as_single_value();
                return *this;
            }
            ensure_size(other.size());
            PROFILE_SCOPE("dynamic_simd_vector *= other, size: " + std::to_string(this->size()));
            std::transform(this->begin(), this->end(), other.begin(), this->begin(),
                           std::multiplies<FieldValueType>());
            return *this;
        }

        dynamic_simd_vector& operator*=(const FieldValueType& alpha) {
            PROFILE_SCOPE("dynamic_simd_vector *= alpha, size: " + std::to_string(this->size()));
            for (auto it = this->begin(); it != this->end(); it++) *it *= alpha;
            return *this;
        }

        dynamic_simd_vector pow(size_t power) const {
            dynamic_simd_vector result = *this;

            if (power == 1) {
                return result;
            }

            PROFILE_SCOPE("dynamic_simd_vector::pow, size: " + std::to_string(this->size()));

            for (std::size_t i = 0; i < result.size(); ++i) {
                result[i] = result[i].pow(power);
            }

            return result;
        }
    };
}  // namespace nil::crypto3::math

// As our operator== returns false for vectors with different sizes, the same will happen here,
// resized vector will have a different hash from the initial one.
template<typename FieldValueType, typename Allocator>
struct std::hash<nil::crypto3::math::dynamic_simd_vector<FieldValueType, Allocator>> {
    std::hash<FieldValueType> value_hasher;

    std::size_t operator()(
        const nil::crypto3::math::dynamic_simd_vector<FieldValueType, Allocator>& v) const {
        std::size_t result = 0;
        for (const auto& val : v) {
            boost::hash_combine(result, value_hasher(val));
        }
        return result;
    }
};

#endif