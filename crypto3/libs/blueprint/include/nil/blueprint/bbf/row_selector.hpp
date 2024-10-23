//---------------------------------------------------------------------------//
// Copyright (c) 2024 Martun Karapetyan <martun@nil.foundation>
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
// @file Contains a class for selecting a set of rows for a given constraint.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_PLONK_BBF_ROW_SELECTOR_HPP
#define CRYPTO3_BLUEPRINT_PLONK_BBF_ROW_SELECTOR_HPP

#include <sstream>
#include <vector>

namespace nil {
    namespace blueprint {
        namespace bbf {

            // This class stores a selector for rows. It uses vector<bool> to store which row is selected and which
            // is not, but provides an const_iterator that pretends to be similar to set<std::size_t>, so it's possible
            // to iterate over the indices.
            class row_selector {
            public:
                row_selector(std::size_t max_rows)
                    : used_rows_(max_rows)
                    , size_(0) {
                }

                void set_row(std::size_t row) {
                    used_rows_.at(row) = true;
                    ++size_;
                }

                bool is_set(std::size_t row) const {
                    return used_rows_.at(row);
                }

                bool operator==(const row_selector& other) {
                    return size_ == other.size_ && used_rows_ == other.used_rows_;
                }

                // Iterator class
                class const_iterator {
                public:
                    using value_type = size_t;  // Type of value returned by const_iterator
                    using difference_type = std::ptrdiff_t;
                    using pointer = value_type*;
                    using reference = value_type&;
                    using const_iterator_category = std::forward_const_iterator_tag;
                
                    const_iterator(const std::vector<bool>& v, size_t pos) : vec(v), index(pos) {
                        // Move to the next true index if the current is false
                        while (index < vec.size() && !vec[index]) {
                            ++index;
                        }
                    }
                
                    // Dereference operator returns the current index
                    size_t operator*() const {
                        return index;
                    }
                
                    // Increment operator
                    const_iterator& operator++() {
                        ++index;
                        // Move to the next true index
                        while (index < vec.size() && !vec[index]) {
                            ++index;
                        }
                        return *this;
                    }

                    // Decrement operator
                    const_iterator& operator--() {
                        if (index > 0) {
                            --index;
                        }
                        // Move to the previous true index
                        while (index > 0 && !vec[index]) {
                            --index;
                        }
                        return *this;
                    }
 
                    // Comparison operators
                    bool operator==(const const_iterator& other) const {
                        return index == other.index;
                    }
                
                    bool operator!=(const const_iterator& other) const {
                        return index != other.index;
                    }

                    
                private:
                    const std::vector<bool>& vec;  // Reference to the underlying vector
                    size_t index;        // Current index
                };
                
                // Begin and end functions returning custom const_iterators
                const_iterator begin() {
                    return const_iterator(vec, 0);  // Start from the beginning
                }
                
                const_iterator end() {
                    return const_iterator(vec, vec.size());  // End at the size of the vector
                }

                std::size_t size() const {
                    return size_;
                }

                bool empty() const {
                    return size_ == 0;
                }

                row_selector& operator|=(const row_selector& other) {
                    if (this->used_rows_.size() < other.used_rows_.size()) {
                        this->used_rows_.resize(other.used_rows_.size());
                    }
                    for (std::size i = 0; i < other.used_rows_.size(); ++i) {
                        if (other.used_rows_[i] && !used_rows_[i]) {
                            used_rows_[i] = true;
                            size_++;
                        }
                    }
                    return *this;
                }

            private:
                // Contains true if selector is enabled for the given row.
                vector<bool> used_rows_; 

                // Size must contain the number of 'true' elements in 'used_rows_'.
                std::size_t size_;

            };

        } // namespace bbf
    } // namespace blueprint
} // namespace nil

#endif // CRYPTO3_BLUEPRINT_PLONK_BBF_ROW_SELECTOR_HPP
