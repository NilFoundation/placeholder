//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
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

#ifndef CRYPTO3_ZK_PLONK_LOOKUP_CONSTRAINT_HPP
#define CRYPTO3_ZK_PLONK_LOOKUP_CONSTRAINT_HPP

#include <nil/crypto3/detail/type_traits.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType>
                class lookup_input_constraints : public std::vector<crypto3::zk::snark::plonk_constraint<FieldType>> {
                public:
                    using constraint_type = crypto3::zk::snark::plonk_constraint<FieldType>;
                    using base_type = std::vector<constraint_type>;
                    using expression_type = typename constraint_type::base_type;

                    // Using the base class's constructors
                    using std::vector<constraint_type>::vector; // Inherit constructors

                    // Constructor to initialize from std::vector
                    lookup_input_constraints(const base_type& other)
                        : base_type(other) {}

                    // Multiply each element with an expression.
                    lookup_input_constraints& operator*=(const expression_type& other) {
                        for (auto& element : *this) {
                            element *= other;
                        }
                        return *this;
                    }

                    lookup_input_constraints operator*(const expression_type& other) const {
                        lookup_input_constraints result = *this;
                        result *= other;
                        return result;
                    }

                    // Allow multiplication with any container of the same type.
                    template <typename Container>
                    typename std::enable_if_t<
                            nil::crypto3::detail::is_range<Container>::value && (
                                std::is_same<typename Container::value_type, expression_type>::value ||
                                std::is_same<typename Container::value_type, constraint_type>::value),
                        lookup_input_constraints>& operator*=(const Container& other) {
                        if (this->size() < other.size())
                            this->resize(other.size());

                        auto it1 = this->begin();
                        auto it2 = other.begin();
                        for (; it2 != other.end(); ++it1, ++it2) {
                            *it1 *= *it2;
                        }
                        return *this;
                    }

                    template <typename Container>
                    typename std::enable_if_t<
                            nil::crypto3::detail::is_range<Container>::value && (
                                std::is_same<typename Container::value_type, expression_type>::value ||
                                std::is_same<typename Container::value_type, constraint_type>::value),
                            lookup_input_constraints>
                    operator*(const Container& other) const {
                        lookup_input_constraints result = *this;
                        result *= other;
                        return result;
                    }

                    // Allow addition with any container of the same type.
                    template <typename Container>
                    typename std::enable_if_t<
                            nil::crypto3::detail::is_range<Container>::value && (
                                std::is_same<typename Container::value_type, expression_type>::value ||
                                std::is_same<typename Container::value_type, constraint_type>::value),
                            lookup_input_constraints>& operator+=(const Container& other) {
                        if (this->size() < other.size())
                            this->resize(other.size());

                        auto it1 = this->begin();
                        auto it2 = other.begin();
                        for (; it2 != other.end(); ++it1, ++it2) {
                            *it1 += *it2;
                        }
                        return *this;
                    }

                    template <typename Container>
                    typename std::enable_if_t<
                            nil::crypto3::detail::is_range<Container>::value && (
                                std::is_same<typename Container::value_type, expression_type>::value ||
                                std::is_same<typename Container::value_type, constraint_type>::value),
                            lookup_input_constraints>
                    operator+(const Container& other) const {
                        lookup_input_constraints result = *this;
                        result += other;
                        return result;
                    }

                    // Allow subtraction with any container of the same type.
                    template <typename Container>
                    typename std::enable_if_t<
                            nil::crypto3::detail::is_range<Container>::value && (
                                std::is_same<typename Container::value_type, expression_type>::value ||
                                std::is_same<typename Container::value_type, constraint_type>::value),
                            lookup_input_constraints>& operator-=(const Container& other) {
                        if (this->size() < other.size())
                            this->resize(other.size());

                        auto it1 = this->begin();
                        auto it2 = other.begin();
                        for (; it2 != other.end(); ++it1, ++it2) {
                            *it1 -= *it2;
                        }
                        return *this;
                    }

                    template <typename Container>
                    typename std::enable_if_t<
                            nil::crypto3::detail::is_range<Container>::value && (
                                std::is_same<typename Container::value_type, expression_type>::value ||
                                std::is_same<typename Container::value_type, constraint_type>::value),
                            lookup_input_constraints>
                    operator-(const Container& other) const {
                        lookup_input_constraints result = *this;
                        result -= other;
                        return result;
                    }
                };


                template<typename FieldType, typename VariableType = plonk_variable<typename FieldType::value_type>>
                class plonk_lookup_constraint {
                public:
                    using field_type = FieldType;
                    using variable_type = VariableType;
                    using term_type = term<VariableType>;
                    using constraint_type = plonk_constraint<FieldType>;

                    std::size_t table_id;
                    lookup_input_constraints<FieldType> lookup_input;

                    bool operator==(const plonk_lookup_constraint &other) const {
                        return table_id == other.table_id && lookup_input == other.lookup_input;
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_LOOKUP_CONSTRAINT_HPP
