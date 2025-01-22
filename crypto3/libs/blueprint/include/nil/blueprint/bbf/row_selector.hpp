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
// @file Contains an optimal row selector class based on boost::dynamic_bitset.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_PLONK_BBF_ROW_SELECTOR_HPP
#define CRYPTO3_BLUEPRINT_PLONK_BBF_ROW_SELECTOR_HPP

#include <sstream>
#include <boost/dynamic_bitset.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {

            // This class stores a selector for rows. It uses boost::dynamic_bitset to store which row is selected and which
            // is not, but provides an const_iterator that pretends to be similar to set<std::size_t>, so it's possible
            // to iterate over the indices.
            template<typename BLOCK = unsigned int>
            class row_selector {
            public:
                // Using boost::dynamic_bitset to store presence of indices
                using BitSet = boost::dynamic_bitset<BLOCK>;

                row_selector(std::size_t max_rows)
                    : used_rows_(max_rows) {
                }

                void set_row(std::size_t row) {
                    if (row < max_index()) {
                        used_rows_[row] = true;
                    }
                }

                void set_interval(std::size_t start_row, std::size_t end_row) {
                    BOOST_ASSERT( end_row < used_rows_.size());
                    BOOST_ASSERT( start_row < end_row );
                    if (start_row  < end_row && end_row < used_rows_.size()) {
                        used_rows_.set(start_row, end_row-start_row + 1, true);
                    }
                }

                bool is_set(std::size_t row) const {
                    return used_rows_.at(row);
                }

                bool operator==(const row_selector& other) const {
                    return used_rows_ == other.used_rows_;
                }

                bool operator[](size_t row) const {
                    return used_rows_.at(row);
                }

                // Iterator class
                class const_iterator {
                public:
                    using value_type = size_t;  // Type of value returned by const_iterator
                    using difference_type = std::ptrdiff_t;
                    using pointer = value_type*;
                    using reference = value_type&;
                    using iterator_category = std::forward_iterator_tag;

                    const_iterator(const BitSet& v, size_t pos)
                        : bitset(v) {
                        if (pos < bitset.size() && bitset[pos])
                            index = pos;
                        else
                            index = bitset.find_next(pos);
                    }

                    // Dereference operator returns the current index
                    size_t operator*() const {
                        return index;
                    }

                    // Increment operator
                    const_iterator& operator++() {
                        index = bitset.find_next(index);
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
                    const BitSet& bitset;   // Reference to the underlying bitset.
                    size_t index;        // Current index
                };

                // Begin and end functions returning custom const_iterators
                const_iterator begin() const {
                    return const_iterator(used_rows_, 0);
                }

                const_iterator end() const {
                    return const_iterator(used_rows_, used_rows_.size());
                }

                // This is NOT maximal size, this is the number of true values in the set.
                std::size_t size() const {
                    return used_rows_.count();
                }

                // This one is the maximal allowed index, I.E. the actual size.
                std::size_t max_index() const {
                    return used_rows_.size();
                }

                bool empty() const {
                    return used_rows_.none();
                }

                bool intersects(const row_selector& other) const {
                    return used_rows_.intersects(other.used_rows_);
                }

                // TODO: delete this, if not used.
                /*
                row_selector& operator|=(const row_selector& other) {
                    if (this->used_rows_.size() < other.used_rows_.size()) {
                        this->used_rows_.resize(other.used_rows_.size());
                        this->used_rows_ |= other.used_rows_;
                    } else if (this->used_rows_.size() > other.used_rows_.size()) {
                        // Here we can't resize other, so we need to make a copy.
                        // In practice our code will always have bitmaps of equal size, so this will
                        // never happen in practice.
                        row_selector other_copy = other;
                        other_copy.used_rows_.resize(this->used_rows_.size());
                        this->used_rows_ |= other_copy.used_rows_;
                    } else {
                        this->used_rows_ |= other.used_rows_;
                    }
                    return *this;
                }*/


                row_selector& operator<<=(size_t bitcount) {
                    used_rows_ <<= bitcount;
                    return *this;
                }

                row_selector& operator>>=(size_t bitcount) {
                    used_rows_ >>= bitcount;
                    return *this;
                }

                template<typename BLOCK2>
                friend std::size_t hash_value(const row_selector<BLOCK2>& a);

                template<typename BLOCK2>
                friend std::ostream& operator<<(std::ostream& os, const row_selector<BLOCK2>& rows);

            private:
                // Contains true if selector is enabled for the given row.
                BitSet used_rows_;
            };

            template<typename BLOCK>
            inline std::size_t hash_value(const row_selector<BLOCK>& bitset) {
                return hash_value(bitset.used_rows_);
            }

            template<typename BLOCK = unsigned int>
            std::ostream& operator<<(std::ostream& os, const row_selector<BLOCK>& rows) {
                // NOTE: os << rows.used_rows_ prints in the reversed order, which is harder to read.
                for (size_t i = 0; i < std::min(size_t(16), rows.used_rows_.size()); i++) {
                    os << rows.used_rows_[i];
                }
                if (rows.used_rows_.size() > 16) {
                    os << "...";
                }
                return os;
            }

        } // namespace bbf
    } // namespace blueprint
} // namespace nil


// Make our row_selector hashable, in the most efficient way, buy accessing the internal storage of the bitset.
namespace std {
    template<typename BLOCK>
    struct hash<nil::blueprint::bbf::row_selector<BLOCK>> {
        std::size_t operator()(const nil::blueprint::bbf::row_selector<BLOCK>& bitset) const {
            boost::hash<nil::blueprint::bbf::row_selector<BLOCK>> hasher;
            return hasher(bitset);
        }
    };
}

#endif // CRYPTO3_BLUEPRINT_PLONK_BBF_ROW_SELECTOR_HPP
