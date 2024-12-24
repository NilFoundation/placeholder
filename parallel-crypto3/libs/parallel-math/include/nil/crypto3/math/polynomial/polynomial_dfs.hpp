//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
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

#ifndef PARALLEL_CRYPTO3_MATH_POLYNOMIAL_POLYNOM_DFT_HPP
#define PARALLEL_CRYPTO3_MATH_POLYNOMIAL_POLYNOM_DFT_HPP

#ifdef CRYPTO3_MATH_POLYNOMIAL_POLYNOM_DFT_HPP
#error "You're mixing parallel and non-parallel crypto3 versions"
#endif

#include <algorithm>
#include <limits>
#include <memory>
#include <vector>
#include <ostream>
#include <iterator>
#include <unordered_map>

#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/polynomial/basic_operations.hpp>
#include <nil/crypto3/math/polynomial/polynomial.hpp>

#include <nil/actor/core/thread_pool.hpp>
#include <nil/actor/core/parallelization_utils.hpp>

namespace nil {
    namespace crypto3 {
        namespace math {
            //size_t __global_from_coefficients_counter_test = 0;
            //size_t __global_coefficients_counter_test = 0;
            // Optimal val.size must be power of two, if it's not true we have points that we will never use
            template<typename FieldValueType, typename Allocator = std::allocator<FieldValueType>>
            class polynomial_dfs {
                typedef std::vector<FieldValueType, Allocator> container_type;

                container_type val;
                size_t _d;

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

                typedef sycl::buffer<value_type> buffer_type;

                // Default constructor creates a zero polynomial of degree 0 and size 1.
                polynomial_dfs() : val(1, FieldValueType::zero()), _d(0) {
                }

                explicit polynomial_dfs(size_t d, size_type n) : val(n, FieldValueType::zero()), _d(d) {
                    BOOST_ASSERT_MSG(n == detail::power_of_two(n), "DFS optimal polynomial size must be a power of two");
                }

                explicit polynomial_dfs(size_t d, size_type n, const allocator_type& a) : val(n, FieldValueType::zero(), a), _d(d) {
                    BOOST_ASSERT_MSG(n == detail::power_of_two(n), "DFS optimal polynomial size must be a power of two");
                }

                polynomial_dfs(size_t d, size_type n, const value_type& x) : val(n, x), _d(d) {
                    BOOST_ASSERT_MSG(n == detail::power_of_two(n), "DFS optimal polynomial size must be a power of two");
                }

                polynomial_dfs(size_t d, size_type n, const value_type& x, const allocator_type& a) :
                    val(n, x, a), _d(d) {
                    BOOST_ASSERT_MSG(n == detail::power_of_two(n), "DFS optimal polynomial size must be a power of two");
                }

                template<typename InputIterator>
                polynomial_dfs(size_t d, InputIterator first, InputIterator last) : val(first, last), _d(d) {
                    BOOST_ASSERT_MSG(
                        std::size_t(std::distance(first, last)) == detail::power_of_two(std::distance(first, last)),
                        "DFS optimal polynomial size must be a power of two");
                }

                template<typename InputIterator>
                polynomial_dfs(size_t d, InputIterator first, InputIterator last, const allocator_type& a) :
                    val(first, last, a), _d(d) {
                    BOOST_ASSERT_MSG(
                        std::size_t(std::distance(first, last)) == detail::power_of_two(std::distance(first, last)),
                        "DFS optimal polynomial size must be a power of two");
                }

                ~polynomial_dfs() = default;

                polynomial_dfs(const polynomial_dfs& x) : val(x.val), _d(x._d) {
                }

                polynomial_dfs(const polynomial_dfs& x, const allocator_type& a) : val(x.val, a), _d(x._d) {
                }

                polynomial_dfs(std::size_t d, std::initializer_list<value_type> il) : val(il), _d(d) {
                }

                polynomial_dfs(size_t d, std::initializer_list<value_type> il, const allocator_type& a) :
                    val(il, a), _d(d) {
                    BOOST_ASSERT_MSG(val.size() == detail::power_of_two(val.size()),
                                     "DFS optimal polynomial size must be a power of two");
                }
                // TODO: add constructor with omega

                polynomial_dfs(polynomial_dfs&& x)
                    BOOST_NOEXCEPT(std::is_nothrow_move_constructible<allocator_type>::value)
                    : val(std::move(x.val))
                    , _d(x._d) {
                }

                polynomial_dfs(polynomial_dfs&& x, const allocator_type& a)
                    : val(std::move(x.val), a)
                    , _d(x._d) {
                }

                polynomial_dfs(size_t d, const container_type& c) : val(c), _d(d) {
                    BOOST_ASSERT_MSG(val.size() == detail::power_of_two(val.size()),
                                     "DFS optimal polynomial size must be a power of two");
                }

                polynomial_dfs(size_t d, container_type&& c) : val(c), _d(d) {
                    BOOST_ASSERT_MSG(val.size() == detail::power_of_two(val.size()),
                                     "DFS optimal polynomial size must be a power of two");
                }

                polynomial_dfs& operator=(const polynomial_dfs& x) {
                    val = x.val;
                    _d = x._d;
                    return *this;
                }

                polynomial_dfs& operator=(polynomial_dfs&& x) {
                    val = std::move(x.val);
                    _d = x._d;
                    return *this;
                }

                bool operator==(const polynomial_dfs& rhs) const {
                    return val == rhs.val && _d == rhs._d;
                }
                bool operator!=(const polynomial_dfs& rhs) const {
                    return !(rhs == *this && _d == rhs._d);
                }

                allocator_type get_allocator() const BOOST_NOEXCEPT {
                    return this->val.__alloc();
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

                size_type size() const BOOST_NOEXCEPT {
                    return val.size();
                }

                size_type degree() const BOOST_NOEXCEPT {
                    return _d;
                }

                void set_degree(size_type d) {
                    _d = d;
                }

                size_type max_degree() const BOOST_NOEXCEPT {
                    return this->size();
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

                void resize(size_type _sz,
                            std::shared_ptr<evaluation_domain<typename value_type::field_type>> old_domain = nullptr,
                            std::shared_ptr<evaluation_domain<typename value_type::field_type>> new_domain = nullptr) {
                    if (this->size() == _sz)
                    {
                        return;
                    }
                    BOOST_ASSERT_MSG(_sz >= _d, "Resizing DFS polynomial to a size less than degree is prohibited: can't restore the polynomial in the future.");

                    if (this->degree() == 0) {
                        // Here we cannot write this->val.resize(_sz, this->val[0]), it will segfault.
                        auto value = this->val[0];
                        this->val.resize(_sz, value);
                    } else {
                        typedef typename value_type::field_type FieldType;
                        if (old_domain == nullptr) {
                            old_domain = make_evaluation_domain<FieldType>(this->size());
                        } else {
                            BOOST_ASSERT_MSG(old_domain->size() == this->size(), "Old domain size is not equal to the polynomial size");
                        }
                        old_domain->inverse_fft(this->val);
                        this->val.resize(_sz, FieldValueType::zero());
                        if (new_domain == nullptr) {
                            new_domain = make_evaluation_domain<FieldType>(_sz);
                        } else {
                            BOOST_ASSERT_MSG(new_domain->size() == _sz, "New domain size is not equal to the polynomial size");
                        }
                        new_domain->fft(this->val);
                    }
                }

                void swap(polynomial_dfs& other) {
                    val.swap(other.val);
                    std::swap(_d, other._d);
                }

                FieldValueType evaluate(const FieldValueType& value) const {
                    std::vector<FieldValueType> tmp = this->coefficients();
                    FieldValueType result = FieldValueType::zero();
                    auto end = tmp.end();
                    // TODO(martun): parallelize the lower loop.
                    while (end != tmp.begin()) {
                        result = result * value + *--end;
                    }
                    return result;
                }

                /**
                 * Returns true if polynomial is a zero polynomial.
                 */
                bool is_zero() const {
                    for (const auto& v: val) {
                        if (v != FieldValueType::zero())
                            return false;
                    }
                    return true;
                }

                /**
                 * Returns true if polynomial is a one polynomial.
                 */
                bool is_one() const {
                    for (const auto& v: val) {
                        if (v != FieldValueType::one())
                            return false;
                    }
                    return true;
                }

                inline static polynomial_dfs zero() {
                    return polynomial_dfs();
                }

                inline static polynomial_dfs one() {
                    return polynomial_dfs(0, size_type(1), value_type::one());
                }

                /**
                 * Compute the reverse polynomial up to vector size n (degree n-1).
                 * Below we make use of the reversal endomorphism definition from
                 * [Bostan, Lecerf, & Schost, 2003. Tellegen's Principle in Practice, on page 38].
                 */
                void reverse(std::size_t n) {
                    std::reverse(this->begin(), this->end());
                    this->resize(n);
                }

                /**
                 * Computes the standard polynomial addition, polynomial A + polynomial B,
                 * and stores result in polynomial C.
                 */
                polynomial_dfs operator+(const polynomial_dfs& other) const {
                    polynomial_dfs result = *this;
                    result += other;
                    return result;
                }

                /**
                 * Computes the standard polynomial addition, polynomial A + polynomial B,
                 * and stores result in polynomial A.
                 */
                polynomial_dfs& operator+=(const polynomial_dfs& other) {
                    if (other.size() > this->size()) {
                        this->resize(other.size());
                    }
                    this->_d = std::max(this->_d, other._d);

                    if (this->size() > other.size()) {
                        polynomial_dfs tmp(other);
                        tmp.resize(this->size());

                        in_place_parallel_transform(this->begin(), this->end(), tmp.begin(),
                            [](FieldValueType& v1, const FieldValueType& v2){v1+=v2;});
                        return *this;
                    }

                    in_place_parallel_transform(this->begin(), this->end(), other.begin(),
                            [](FieldValueType& v1, const FieldValueType& v2){v1+=v2;});

                    return *this;
                }

                /**
                 * Computes polynomial A + constant c,
                 * and stores result in polynomial A.
                 */
                polynomial_dfs& operator+=(const FieldValueType& c) {
                    for( auto it = this->begin(); it!=this->end(); it++) *it += c;
                    return *this;
                }

                /**
                 * Computes polynomial A - constant c,
                 * and stores result in polynomial A.
                 */
                polynomial_dfs operator-() const {
                    polynomial_dfs result(this->_d, this->begin(), this->end());
                    parallel_transform(this->begin(), this->end(), result.begin(), std::negate<FieldValueType>());
                    return result;
                }

                /**
                 * Computes the standard polynomial subtraction, polynomial A - polynomial B,
                 * and stores result in polynomial C.
                 */
                polynomial_dfs operator-(const polynomial_dfs& other) const {
                    polynomial_dfs result = *this;
                    result -= other;
                    return result;
                }

                /**
                 * Computes the standard polynomial subtraction, polynomial A - polynomial B,
                 * and stores result in polynomial A.
                 */
                polynomial_dfs& operator-=(const polynomial_dfs& other) {
                    if (other.size() > this->size()) {
                        this->resize(other.size());
                    }
                    this->_d = std::max(this->_d, other._d);

                    if (this->size() > other.size()) {
                        polynomial_dfs tmp(other);
                        tmp.resize(this->size());

                        in_place_parallel_transform(this->begin(), this->end(), tmp.begin(),
                            [](FieldValueType& v1, const FieldValueType& v2){v1-=v2;});

                        return *this;
                    }

                    in_place_parallel_transform(this->begin(), this->end(), other.begin(),
                            [](FieldValueType& v1, const FieldValueType& v2){v1-=v2;});
                    return *this;
                }

                /**
                 * Computes tpolynomial A - constant c
                 * and stores result in polynomial A.
                 */
                polynomial_dfs& operator-=(const FieldValueType& c) {
                    for( auto it = this->begin(); it!=this->end(); it++) *it -= c;
                    return *this;
                }

                /**
                 * Perform the multiplication of two polynomials, polynomial A * polynomial B,
                 * and stores result in polynomial C.
                 */
                polynomial_dfs operator*(const polynomial_dfs& other) const {
                    polynomial_dfs result = *this;
                    result *= other;
                    return result;
                }

                /**
                 * Perform the multiplication of two polynomials, polynomial A * polynomial B,
                 * and stores result in polynomial A.
                 */
                polynomial_dfs& operator*=(const polynomial_dfs& other) {
                    return cached_multiplication(other);
                }

                /**
                 * Performs multiplication of two polynomials, but with domain caches
                 */
                polynomial_dfs& cached_multiplication(
                        const polynomial_dfs& other,
                        std::shared_ptr<evaluation_domain<typename value_type::field_type>> domain = nullptr,
                        std::shared_ptr<evaluation_domain<typename value_type::field_type>> other_domain = nullptr,
                        std::shared_ptr<evaluation_domain<typename value_type::field_type>> new_domain = nullptr) {

                    const size_t polynomial_s =
                        detail::power_of_two(std::max({this->size(), other.size(), this->degree() + other.degree() + 1}));

                    if (this->size() < polynomial_s) {
                        this->resize(polynomial_s, domain, new_domain);
                    }


                    // Change the degree only here, after a possible resize, otherwise we have a polynomial
                    // with a high degree but small size, which sometimes segfaults.
                    this->_d += other._d;

                    if (other.size() < polynomial_s) {
                        polynomial_dfs tmp(other);
                        tmp.resize(polynomial_s, other_domain, new_domain);

                        in_place_parallel_transform(this->begin(), this->end(), tmp.begin(),
                            [](FieldValueType& v1, const FieldValueType& v2){v1*=v2;});
                        return *this;
                    }

                    in_place_parallel_transform(this->begin(), this->end(), other.begin(),
                            [](FieldValueType& v1, const FieldValueType& v2){v1*=v2;});

                    return *this;
                }

                /**
                 * Perform the multiplication of two polynomials, polynomial A * constant alpha,
                 * and stores result in polynomial A.
                 */
                polynomial_dfs& operator*=(const FieldValueType& alpha) {
                    for( auto it = this->begin(); it!=this->end(); it++) *it *= alpha;
                    return *this;
                }

                /**
                 * Perform the standard Euclidean Division algorithm.
                 * Input: Polynomial A, Polynomial B, where A / B
                 * Output: Polynomial Q, such that A = (Q * B) + R.
                 */
                polynomial_dfs operator/(const polynomial_dfs& other) const {
                    std::vector<FieldValueType> x = this->coefficients();
                    std::vector<FieldValueType> y = other.coefficients();
                    std::vector<FieldValueType> r, q;
                    division(q, r, x, y);
                    std::size_t new_s = q.size();

                    typedef typename value_type::field_type FieldType;
                    size_t n = this->size();
                    value_type omega = unity_root<FieldType>(n);
                    q.resize(n);
                    detail::basic_radix2_fft<FieldType>(q, omega);
                    return polynomial_dfs(new_s - 1, q);
                }

                /**
                 * Perform the standard Euclidean Division algorithm.
                 * Input: Polynomial A, Polynomial B, where A / B
                 * Output: Polynomial R, such that A = (Q * B) + R.
                 */
                polynomial_dfs operator%(const polynomial_dfs& other) const {
                    std::vector<FieldValueType> x = this->coefficients();
                    std::vector<FieldValueType> y = other.coefficients();
                    std::vector<FieldValueType> r, q;
                    division(q, r, x, y);
                    std::size_t new_s = r.size();

                    typedef typename value_type::field_type FieldType;
                    size_t n = this->size();
                    value_type omega = unity_root<FieldType>(n);
                    r.resize(n);
                    detail::basic_radix2_fft<FieldType>(r, omega);
                    return polynomial_dfs(new_s - 1, r);
                }

                template<typename ContainerType>
                void from_coefficients(const ContainerType &tmp) {
                    typedef typename value_type::field_type FieldType;
                    size_t n = detail::power_of_two(tmp.size());
                    value_type omega = unity_root<FieldType>(n);
                    _d = tmp.size() - 1;
                    val.assign(tmp.begin(), tmp.end());
                    val.resize(n, FieldValueType::zero());
                    detail::basic_radix2_fft<FieldType>(val, omega);
                }

                std::vector<FieldValueType> coefficients(
                        std::shared_ptr<evaluation_domain<typename value_type::field_type>> domain = nullptr) const {
                    typedef typename value_type::field_type FieldType;
                    value_type omega = unity_root<FieldType>(this->size());
                    std::vector<FieldValueType> tmp(this->begin(), this->end());

                    if (domain == nullptr) {
                        detail::basic_radix2_fft<FieldType>(tmp, omega.inversed());
                        const value_type sconst = value_type(this->size()).inversed();
                        parallel_transform(tmp.begin(), tmp.end(),tmp.begin(),
                            std::bind(std::multiplies<value_type>(), sconst, std::placeholders::_1));
                    } else {
                        domain->inverse_fft(tmp);
                    }

                    size_t r_size = tmp.size();
                    while (r_size > 1 && tmp[r_size - 1] == FieldValueType::zero()) {
                        --r_size;
                    }
                    tmp.resize(r_size);
                    return tmp;
                }

                polynomial_dfs pow(size_t power) const {
                    polynomial_dfs result = *this;

                    if (power == 1) {
                        return result;
                    }

                    size_t expected_size = detail::power_of_two(
                        std::max({this->size(), this->degree() * power + 1}));
                    result.resize(expected_size);
                    result._d = _d * power;

                    for (std::size_t i = 0; i < result.size(); ++i) {
                        result[i] = result[i].pow(power);
                    }

                    return result;
                }

            };

            template<typename FieldValueType, typename Allocator = std::allocator<FieldValueType>,
                     typename = typename std::enable_if<detail::is_field_element<FieldValueType>::value>::type>
            polynomial_dfs<FieldValueType, Allocator> operator+(const polynomial_dfs<FieldValueType, Allocator>& A,
                                                            const FieldValueType& B) {
                polynomial_dfs<FieldValueType> result(A);
                for( auto it = result.begin(); it != result.end(); it++ ){
                    *it += B;
                }
                return result;
            }

            template<typename FieldValueType, typename Allocator = std::allocator<FieldValueType>,
                     typename = typename std::enable_if<detail::is_field_element<FieldValueType>::value>::type>
            polynomial_dfs<FieldValueType, Allocator> operator+(const FieldValueType& A,
                                                            const polynomial_dfs<FieldValueType, Allocator>& B) {
                polynomial_dfs<FieldValueType> result(B);
                for( auto it = result.begin(); it != result.end(); it++ ){
                    *it += A;
                }
                return result;
            }


            template<typename FieldValueType, typename Allocator = std::allocator<FieldValueType>,
                     typename = typename std::enable_if<detail::is_field_element<FieldValueType>::value>::type>
            polynomial_dfs<FieldValueType, Allocator> operator-(const polynomial_dfs<FieldValueType, Allocator>& A,
                                                            const FieldValueType& B) {
                polynomial_dfs<FieldValueType> result(A);
                for( auto it = result.begin(); it != result.end(); it++ ){
                    *it -=  B;
                }
                return result;
            }

            template<typename FieldValueType, typename Allocator = std::allocator<FieldValueType>,
                     typename = typename std::enable_if<detail::is_field_element<FieldValueType>::value>::type>
            polynomial_dfs<FieldValueType, Allocator> operator-(const FieldValueType& A,
                                                            const polynomial_dfs<FieldValueType, Allocator>& B) {
                polynomial_dfs<FieldValueType> result(B);
                for( auto it = result.begin(); it != result.end(); it++ ){
                    *it = A - *it;
                }
                return result;
            }

            template<typename FieldValueType, typename Allocator = std::allocator<FieldValueType>,
                     typename = typename std::enable_if<detail::is_field_element<FieldValueType>::value>::type>
            polynomial_dfs<FieldValueType, Allocator> operator*(const polynomial_dfs<FieldValueType, Allocator>& A,
                                                            const FieldValueType& B) {

                polynomial_dfs<FieldValueType> result(A);
                parallel_foreach(result.begin(), result.end(),
                    [&B](FieldValueType& v) {
                        v *= B;
                    }, ThreadPool::PoolLevel::LOW);
                return result;
            }

            template<typename FieldValueType, typename Allocator = std::allocator<FieldValueType>,
                     typename = typename std::enable_if<detail::is_field_element<FieldValueType>::value>::type>
            polynomial_dfs<FieldValueType, Allocator> operator*(const FieldValueType& A,
                                                            const polynomial_dfs<FieldValueType, Allocator>& B) {
                // Call the upper function.
                return B * A;
            }

            template<typename FieldValueType, typename Allocator = std::allocator<FieldValueType>,
                     typename = typename std::enable_if<detail::is_field_element<FieldValueType>::value>::type>
            polynomial_dfs<FieldValueType, Allocator> operator/(const polynomial_dfs<FieldValueType, Allocator>& A,
                                                            const FieldValueType& B) {
                polynomial_dfs<FieldValueType> result(A);
                FieldValueType B_inversed = B.inversed();
                parallel_foreach(result.begin(), result.end(),
                    [&B_inversed](FieldValueType& v) {
                        v *= B_inversed;
                    }, ThreadPool::PoolLevel::LOW);

                return result;
            }

            template<typename FieldValueType, typename Allocator = std::allocator<FieldValueType>,
                     typename = typename std::enable_if<detail::is_field_element<FieldValueType>::value>::type>
            polynomial_dfs<FieldValueType, Allocator> operator/(const FieldValueType& A,
                                                            const polynomial_dfs<FieldValueType, Allocator>& B) {

                return polynomial_dfs<FieldValueType>(0, B.size(), A) / B;
            }

            // Used in the unit tests, so we can use BOOST_CHECK_EQUALS, and see
            // the values of polynomials, when the check fails.
            template<typename FieldValueType, typename Allocator = std::allocator<FieldValueType>,
                     typename = typename std::enable_if<detail::is_field_element<FieldValueType>::value>::type>
            std::ostream& operator<<(std::ostream& os,
                                     const polynomial_dfs<FieldValueType, Allocator>& poly) {
                if (poly.degree() == 0) {
                    // If all it contains is a constant, print the constant, so it's more readable.
                    os << *poly.begin();
                } else {
                    os << "[Polynomial DFS, size " << poly.size()
                       << " degree " << poly.degree() << " values ";
                    os << std::hex;
                    for(auto it = poly.begin(); it != poly.end(); ++it) {
                        os << "0x" << it->data;
                        if (it != std::prev(poly.end())) {
                            os << ", ";
                        }
                    }
                    os << std::dec << "]";
                }
                return os;
            }

            template<typename FieldType>
            static inline polynomial_dfs<typename FieldType::value_type> polynomial_sum(
                    std::vector<math::polynomial_dfs<typename FieldType::value_type>> addends) {
                using FieldValueType = typename FieldType::value_type;

                if (addends.empty()) {
                    return {};
                }

                // Since there are only ~20 addends, we will just use that many maps
                std::vector<std::unordered_map<std::size_t, polynomial_dfs<FieldValueType>>> maps(addends.size());
                for (size_t i = 0; i < addends.size(); ++i) {
                    maps[i][addends[i].size()] = std::move(addends[i]);
                }

                for (std::size_t stride = 1; stride < addends.size(); stride <<= 1) {
                    std::size_t double_stride = stride << 1;
                    std::size_t max_i = (addends.size() - stride) / double_stride;
                    if ((addends.size() - stride) % double_stride != 0) {
                        max_i++;
                    }

                    parallel_for(0, max_i, [&, stride, double_stride](std::size_t i) {
                        std::size_t index1 = i * double_stride;
                        std::size_t index2 = index1 + stride;
                        if (index2 < addends.size()) {
                            auto& map1 = maps[index1];
                            auto& map2 = maps[index2];

                            for (auto& entry : map2) {
                                auto it = map1.find(entry.first);
                                if (it != map1.end()) {
                                    it->second += entry.second;
                                } else {
                                    map1[entry.first] = std::move(entry.second);
                                }
                            }
                            map2.clear();
                        }
                    });
                }

                std::unordered_map<std::size_t, polynomial_dfs<FieldValueType>>& size_to_part_sum = maps[0];
                std::vector<polynomial_dfs<FieldValueType>> grouped_addends;

                std::size_t max_size = 0;
                for (const auto& [size, partial_sum] : size_to_part_sum) {
                    max_size = std::max(max_size, size);
                    grouped_addends.push_back(std::move(partial_sum));
                }

                std::vector<polynomial<FieldValueType>> grouped_addends_coefs(grouped_addends.size());

                nil::crypto3::parallel_for(0, grouped_addends.size(), [&grouped_addends_coefs, &grouped_addends] (std::size_t i) {
                    grouped_addends_coefs[i] = grouped_addends[i].coefficients();
                }, ThreadPool::PoolLevel::HIGH);

                // We can parallelize this by adding pairwise, like it's done in multiplication, but it's pretty fast
                // so skipping it for now.
                polynomial<FieldValueType> coef_result;
                for (const auto& partial_sum : grouped_addends_coefs) {
                    coef_result += partial_sum;
                }

                polynomial_dfs<FieldValueType> dfs_result;
                dfs_result.from_coefficients(coef_result.get_storage());

                return dfs_result;
            }

            template<typename FieldType>
            void gpu_fft(
                std::shared_ptr<sycl::buffer<typename FieldType::value_type>> a,
                std::shared_ptr<sycl::buffer<typename FieldType::value_type>> omega_cache
            ) {
                using value_type = typename FieldType::value_type;
                const std::size_t n = a->size(), logn = log2(n);
                if (n != (1u << logn))
                    throw std::invalid_argument("expected n == (1u << logn)");

                // swapping in place (from Storer's book)
                // We can parallelize this look, since k and rk are pairs, they will never intersect.
                sycl::queue fft_queue(sycl::gpu_selector{});
                fft_queue.submit([&](sycl::handler &cgh) {
                    auto acc = a->template get_access<sycl::access::mode::write>(cgh);
                    cgh.parallel_for(sycl::range<1>(a->size()), [=](sycl::id<1> idx) {
                        const std::size_t r_idx = crypto3::math::detail::bitreverse(idx, logn);
                        if (idx < r_idx)
                            std::swap(acc[idx], acc[r_idx]);
                    });
                });
                fft_queue.wait();

                // invariant: m = 2^{s-1}
                value_type t;
                for (std::size_t s = 1, m = 1, inc = n / 2; s <= logn; ++s, m <<= 1, inc >>= 1) {
                    // w_m is 2^s-th root of unity now
                    // Here we can parallelize on the both loops with 'k' and 'm', because for each value of k and m
                    // the ranges of array 'a' used do not intersect. Think of these 2 loops as 1.
                    const size_t count_k = n / (2 * m) + (n % (2 * m) ? 1 : 0);
                    fft_queue.submit([&](sycl::handler &cgh) {
                        auto acc = a->template get_access<sycl::access::mode::write>(cgh);
                        auto omega_cache_acc = omega_cache->template get_access<sycl::access::mode::read>(cgh);
                        cgh.parallel_for(sycl::range<1>(count_k * m), [=](sycl::id<1> index) {
                            const std::size_t k = (index / m) * m * 2;
                            const std::size_t j = index % m;
                            const std::size_t idx = j * inc;
                            const value_type t = acc[k + j + m] * omega_cache_acc[idx];
                            acc[k + j + m] = acc[k + j] - t;
                            acc[k + j] += t;
                        });
                    });
                    fft_queue.wait();
                }
            }

            template<typename FieldType>
            void gpu_inverse_fft(
                std::shared_ptr<sycl::buffer<typename FieldType::value_type>> a,
                std::shared_ptr<sycl::buffer<typename FieldType::value_type>> fft_cache
            ) {
                using value_type = typename FieldType::value_type;
                gpu_fft<FieldType>(a, fft_cache);

                const value_type sconst = value_type(a->size()).inversed();
                sycl::queue ifft_mul_queue(sycl::gpu_selector{});
                ifft_mul_queue.submit([&](sycl::handler &cgh) {
                    auto acc = a->template get_access<sycl::access::mode::write>(cgh);
                    cgh.parallel_for(sycl::range<1>(a->size()), [=](sycl::id<1> idx) {
                        acc[idx] *= sconst;
                    });
                });
                ifft_mul_queue.wait();
            }

            template<typename FieldType>
            void handle_polynomial_resizing(
                polynomial_dfs<typename FieldType::value_type>& poly,
                std::shared_ptr<sycl::buffer<typename FieldType::value_type>>& buffer,
                std::size_t new_domain_size,
                std::shared_ptr<sycl::buffer<typename FieldType::value_type>> current_domain_buf,
                std::shared_ptr<sycl::buffer<typename FieldType::value_type>> new_domain_buf
            ) {
                using value_type = typename FieldType::value_type;
                using buffer_type = sycl::buffer<value_type>;

                if (poly.size() >= new_domain_size) {
                    return;
                }

                value_type fake_value = value_type::zero();
                if (poly.degree() == 0) {
                    auto value = poly[0];
                    buffer->set_write_back(true);
                    buffer = std::make_shared<buffer_type>(&fake_value, 1);
                    poly.get_storage().resize(new_domain_size, value);
                    buffer = std::make_shared<buffer_type>(
                        poly.data(), poly.size(), sycl::property::buffer::use_host_ptr()
                    );
                } else {
                    gpu_inverse_fft<FieldType>(buffer, current_domain_buf);
                    buffer->set_write_back(true);
                    buffer = std::make_shared<buffer_type>(&fake_value, 1);
                    poly.get_storage().resize(new_domain_size, value_type::zero());
                    buffer = std::make_shared<buffer_type>(
                        poly.data(), poly.size(), sycl::property::buffer::use_host_ptr()
                    );
                    gpu_fft<FieldType>(buffer, new_domain_buf);
                }
                buffer->set_write_back(false);
            }

            template<typename FieldType>
            polynomial_dfs<typename FieldType::value_type> polynomial_product(
                std::vector<math::polynomial_dfs<typename FieldType::value_type>> &&multipliers
            ) {
                using value_type = typename FieldType::value_type;
                using buffer_type = sycl::buffer<value_type>;

                if (multipliers.size() == 0) {
                    return {};
                }
                if (multipliers.size() == 1) {
                    return std::move(multipliers[0]);
                }

                std::unordered_map<std::size_t, std::shared_ptr<evaluation_domain<FieldType>>> domain_cache;

                std::size_t min_domain_size = std::numeric_limits<std::size_t>::max();
                std::size_t max_domain_size = 0;
                std::size_t total_degree = 0;
                std::set<std::size_t> needed_domain_sizes;
                for (std::size_t i = 0; i < multipliers.size(); i++) {
                    min_domain_size = std::min(min_domain_size, multipliers[i].size());
                    max_domain_size = std::max(max_domain_size, multipliers[i].size());
                    total_degree += multipliers[i].degree();
                    needed_domain_sizes.insert(multipliers[i].size());
                }
                max_domain_size = std::max(max_domain_size, detail::power_of_two(total_degree + 1));
                needed_domain_sizes.insert(max_domain_size);

                for (std::size_t domain_size : needed_domain_sizes) {
                    domain_cache[domain_size] = nullptr;
                }

                // We cannot use LOW level thread pool here, make_evaluation_domain uses it.
                parallel_foreach(needed_domain_sizes.begin(), needed_domain_sizes.end(),
                    [&domain_cache](std::size_t domain_size) {
                        domain_cache[domain_size] = make_evaluation_domain<FieldType>(domain_size);
                    }, ThreadPool::PoolLevel::HIGH);

                // create sycl buffers for the multipliers
                std::vector<std::shared_ptr<buffer_type>> multipliers_buf(multipliers.size());
                for (std::size_t i = 0; i < multipliers.size(); ++i) {
                    multipliers_buf[i] = std::make_shared<buffer_type>(
                        multipliers[i].data(), multipliers[i].size(), sycl::property::buffer::use_host_ptr()
                    );
                    multipliers_buf[i]->set_write_back(false);
                }

                // create sycl buffers for the domains
                std::map<std::size_t, std::shared_ptr<buffer_type>> domains_buf_1, domains_buf_2;
                for (std::size_t domain_size : needed_domain_sizes) {
                    auto domain = domain_cache[domain_size];
                    domains_buf_1[domain_size] = std::make_shared<buffer_type>(
                        domain->get_fft_cache()->first.data(), domain->get_fft_cache()->first.size(), sycl::property::buffer::use_host_ptr()
                    );
                    domains_buf_2[domain_size] = std::make_shared<buffer_type>(
                        domain->get_fft_cache()->second.data(), domain->get_fft_cache()->second.size(), sycl::property::buffer::use_host_ptr()
                    );
                }

                // pre-resize the multipliers
                parallel_for(0, multipliers.size(), [&](std::size_t i) {
                    handle_polynomial_resizing<FieldType>(
                        multipliers[i], multipliers_buf[i], max_domain_size,
                        domains_buf_2[multipliers_buf[i]->size()], domains_buf_1[max_domain_size]
                    );
                });

                // multiply the polynomials
                for (std::size_t stride = 1; stride < multipliers.size(); stride <<= 1) {
                    const std::size_t double_stride = stride << 1;
                    // This loop will run in parallel.
                    std::size_t max_i = (multipliers.size() - stride) / double_stride;
                    if ((multipliers.size() - stride) % double_stride != 0)
                        max_i++;

                    // We can't use LOW level thread pool here, it's used in cached_multiplication.
                    parallel_for(0, max_i, [&, stride, double_stride](std::size_t i) {
                        std::size_t index1 = i * double_stride;
                        std::size_t index2 = index1 + stride;

                        sycl::queue mult_queue(sycl::gpu_selector{});
                        mult_queue.submit([&](sycl::handler &cgh) {
                            sycl::accessor acc(*multipliers_buf[index1], cgh, sycl::read_write);
                            sycl::accessor acc2(*multipliers_buf[index2], cgh, sycl::read_only);
                            cgh.parallel_for(sycl::range<1>(multipliers_buf[index1]->size()), [=](sycl::id<1> idx) {
                                acc[idx] *= acc2[idx];
                            });
                        });
                        mult_queue.wait();
                    }, ThreadPool::PoolLevel::HIGH);
                }
                // write back the result
                multipliers_buf[0]->set_write_back(true);
                return std::move(multipliers[0]);
            }

        }    // namespace math
    }        // namespace crypto3
}    // namespace nil

// As our operator== returns false for polynomials with different sizes, the same will happen here,
// resized polynomial will have a different hash from the initial one.
template<typename FieldValueType, typename Allocator>
struct std::hash<nil::crypto3::math::polynomial_dfs<FieldValueType, Allocator>>
{
    std::hash<FieldValueType> value_hasher;

    std::size_t operator()(const nil::crypto3::math::polynomial_dfs<FieldValueType, Allocator>& poly) const
    {
        std::size_t result = poly.degree();
        for (const auto& val: poly) {
            boost::hash_combine(result, value_hasher(val));
        }
        return result;
    }
};

#endif    // CRYPTO3_MATH_POLYNOMIAL_POLYNOM_DFT_HPP
