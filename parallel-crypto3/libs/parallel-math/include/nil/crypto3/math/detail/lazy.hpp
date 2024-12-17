//---------------------------------------------------------------------------//
// Copyright (c) 2024 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#pragma once

#include <vector>
#include <optional>

namespace nil {
    namespace crypto3 {
        namespace math {

            template<typename T>
            class lazy_element {
                std::optional<T> value;
            public:
                typedef typename T::field_type field_type;

                lazy_element() : value(std::nullopt) {}
                lazy_element(const T& value) : value(value) {}
                lazy_element(T&& value) : value(std::move(value)) {}
                lazy_element(const lazy_element& other) : value(other.value) {}

                T& get() {
                    if (!value) {
                        value = T::zero();
                    }
                    return *value;
                }

                operator T() const {
                    return get();
                }

                const T& get() const {
                    if (!value) {
                        return T::zero();
                    }
                    return *value;
                }

                // Arithmetic operations
                lazy_element& operator+=(const T& other) {
                    get() += other;
                    return *this;
                }

                lazy_element& operator+=(const lazy_element& other) {
                    get() += other.get();
                    return *this;
                }

                lazy_element operator+(const T& other) const {
                    lazy_element result(*this);
                    result += other;
                    return result;
                }

                lazy_element operator+(const lazy_element& other) const {
                    lazy_element result(*this);
                    result += other;
                    return result;
                }

                lazy_element operator-(const T& other) const {
                    lazy_element result(*this);
                    result.get() -= other;
                    return result;
                }

                lazy_element operator-(const lazy_element& other) const {
                    lazy_element result(*this);
                    result.get() -= other.get();
                    return result;
                }

                lazy_element& operator-=(const T& other) {
                    get() -= other;
                    return *this;
                }

                lazy_element& operator-=(const lazy_element& other) {
                    get() -= other.get();
                    return *this;
                }

                lazy_element operator*(const T& other) const {
                    lazy_element result;
                    result.get() = get() * other;
                    return result;
                }

                lazy_element operator*(const lazy_element& other) const {
                    lazy_element result;
                    result.get() = get() * other.get();
                    return result;
                }

                lazy_element& operator*=(const T& other) {
                    get() *= other;
                    return *this;
                }

                lazy_element& operator*=(const lazy_element& other) {
                    get() *= other.get();
                    return *this;
                }
            };

            template <typename T, typename Allocator = void>
            class lazy_vector {
                typedef std::vector<lazy_element<T>> container_type;
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

                lazy_vector(size_t size) : val(size) {}
                lazy_vector() : val() {}

                size_type size() const {
                    return val.size();
                }

                container_type& get_storage() {
                    return val;
                }

                iterator begin() BOOST_NOEXCEPT {
                    return val.begin();
                }

                const_iterator begin() const BOOST_NOEXCEPT {
                    return val.begin();
                }
                iterator end() BOOST_NOEXCEPT {
                    return val.end();
                }
                const_iterator end() const BOOST_NOEXCEPT {
                    return val.end();
                }

                reverse_iterator rbegin() BOOST_NOEXCEPT {
                    return val.rbegin();
                }

                const_reverse_iterator rbegin() const BOOST_NOEXCEPT {
                    return val.rbegin();
                }

                reverse_iterator rend() BOOST_NOEXCEPT {
                    return reverse_iterator(begin());
                }

                const_reverse_iterator rend() const BOOST_NOEXCEPT {
                    return const_reverse_iterator(begin());
                }

                const_iterator cbegin() const BOOST_NOEXCEPT {
                    return begin();
                }

                const_iterator cend() const BOOST_NOEXCEPT {
                    return end();
                }

                const_reverse_iterator crbegin() const BOOST_NOEXCEPT {
                    return rbegin();
                }

                const_reverse_iterator crend() const BOOST_NOEXCEPT {
                    return rend();
                }

                size_type capacity() const BOOST_NOEXCEPT {
                    return val.capacity();
                }
                bool empty() const BOOST_NOEXCEPT {
                    return val.empty();
                }
                size_type max_size() const BOOST_NOEXCEPT {
                    return val.max_size();
                }
                void reserve(size_type _n) {
                    return val.reserve(_n);
                }
                void shrink_to_fit() BOOST_NOEXCEPT {
                    return val.shrink_to_fit();
                }

                reference operator[](size_type _n) BOOST_NOEXCEPT {
                    return val[_n];
                }

                const_reference operator[](size_type _n) const BOOST_NOEXCEPT {
                    return val[_n];
                }

                reference at(size_type _n) {
                    return val.at(_n);
                }

                const_reference at(size_type _n) const {
                    return val.at(_n);
                }

                reference front() BOOST_NOEXCEPT {
                    return val.front();
                }
                const_reference front() const BOOST_NOEXCEPT {
                    return val.front();
                }
                reference back() BOOST_NOEXCEPT {
                    return val.back();
                }
                const_reference back() const BOOST_NOEXCEPT {
                    return val.back();
                }

                value_type* data() BOOST_NOEXCEPT {
                    return val.data();
                }

                const value_type* data() const BOOST_NOEXCEPT {
                    return val.data();
                }

                void push_back(const_reference _x) {
                    val.push_back(_x);
                }

                void push_back(value_type&& _x) {
                    val.emplace_back(_x);
                }

                template<class... Args>
                reference emplace_back(Args&&... _args) {
                    return val.template emplace_back<>(_args...);
                }

                void pop_back() {
                    val.pop_back();
                }

                void resize(size_type _new_size) {
                    val.resize(_new_size);
                }

                iterator insert(const_iterator _position, const_reference _x) {
                    return val.insert(_position, _x);
                }

                iterator insert(const_iterator _position, value_type&& _x) {
                    return val.insert(_position, _x);
                }
                template<class... Args>
                iterator emplace(const_iterator _position, Args&&... _args) {
                    return val.template emplace<>(_position, _args...);
                }

                iterator insert(const_iterator _position, size_type _n, const_reference _x) {
                    return val.insert(_position, _n, _x);
                }

                template<class InputIterator>
                iterator insert(const_iterator _position, InputIterator _first, InputIterator _last) {
                    return val.insert(_position, _first, _last);
                }

                iterator insert(const_iterator _position, std::initializer_list<value_type> _il) {
                    return insert(_position, _il.begin(), _il.end());
                }

                iterator erase(const_iterator _position) {
                    return val.erase(_position);
                }

                iterator erase(const_iterator _first, const_iterator _last) {
                    return val.erase(_first, _last);
                }

                void clear() BOOST_NOEXCEPT {
                    val.clear();
                }

            };
        }   // namespace math
    }       // namespace crypto3
}   // namespace nil