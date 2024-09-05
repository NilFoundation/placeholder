#include "zkevm_framework/core/mpt/path.hpp"

#include <algorithm>
#include <stdexcept>

namespace core {
    namespace mpt {

        Path::Path() = default;

        Path::Path(const std::vector<std::byte>& data, std::size_t offset)
            : data_(data), offset_(offset) {}

        int Path::size() const { return data_.size() * 2 - offset_; }

        bool Path::empty() const { return size() == 0; }

        std::byte Path::operator[](size_t idx) const {
            idx += offset_;
            auto target_byte = data_[idx / 2];
            return (idx % 2 == 0) ? (target_byte >> 4) : (target_byte & std::byte{0x0F});
        }

        bool Path::operator==(const Path& other) const {
            if (other.size() != size()) {
                return false;
            }
            for (int i = 0; i < size(); ++i) {
                if (operator[](i) != other[i]) {
                    return false;
                }
            }
            return true;
        }

        std::byte Path::at(std::size_t idx) const {
            if (idx >= size()) {
                throw std::out_of_range("Index out of range");
            }
            return operator[](idx);
        }

        bool Path::StartsWith(const Path& other) const {
            if (other.size() > size()) {
                return false;
            }
            for (int i = 0; i < other.size(); ++i) {
                if (operator[](i) != other[i]) {
                    return false;
                }
            }
            return true;
        }

        Path* Path::Consume(std::size_t amount) {
            offset_ += amount;
            return this;
        }

        Path Path::CommonPrefix(const Path& other) const {
            int least_len = std::min(size(), other.size());
            int common_len = 0;
            for (int i = 0; i < least_len; ++i) {
                if (operator[](i) != other[i]) {
                    break;
                }
                common_len += 1;
            }
            return ConstructFromPrefix(common_len);
        }

        Path Path::operator+(const Path& other) const {
            std::size_t final_size = size() + other.size();
            bool final_is_odd = (final_size % 2) == 1;
            std::vector<std::byte> new_data;
            new_data.reserve((final_size + 1) / 2);  // Round up to nearest byte

            auto at_combined = [this, &other](std::size_t n) -> std::byte {
                if (n < this->size()) {
                    return operator[](n);
                }
                return other[n - this->size()];
            };

            if (final_is_odd) {
                new_data.push_back(at_combined(0) & std::byte{0x0F});
            }

            for (std::size_t i = final_is_odd ? 1 : 0; i < final_size; i += 2) {
                std::byte next_byte =
                    (at_combined(i) << 4) | (at_combined(i + 1) & std::byte{0x0F});
                new_data.push_back(next_byte);
            }

            return Path(new_data, final_is_odd ? 1 : 0);
        }

        Path Path::ConstructFromPrefix(std::size_t length) const {
            std::vector<std::byte> new_data;
            bool is_odd_len = length % 2 == 1;
            std::size_t pos = 0;
            if (is_odd_len) {
                new_data.push_back(operator[](pos));
                pos += 1;
            }
            for (; pos < length; pos += 2) {
                new_data.push_back((operator[](pos) << 4) | operator[](pos + 1));
            }
            std::size_t new_offset = is_odd_len ? 1 : 0;
            return Path(new_data, new_offset);
        }

    }  // namespace mpt
}  // namespace core
