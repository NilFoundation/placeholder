#ifndef ZKEMV_FRAMEWORK_LIBS_NIL_CORE_INCLUDE_ZKEVM_FRAMEWORK_CORE_MPT_PATH_HPP_
#define ZKEMV_FRAMEWORK_LIBS_NIL_CORE_INCLUDE_ZKEVM_FRAMEWORK_CORE_MPT_PATH_HPP_

#include <cstddef>
#include <cstdint>
#include <ssz++.hpp>
#include <vector>

namespace core {
    namespace mpt {

        class Path : public ssz::ssz_variable_size_container {
          public:
            Path();
            Path(const Path &other) = default;
            Path(const std::vector<std::byte> &data, std::size_t offset = 0);

            int size() const;
            bool empty() const;
            std::byte operator[](size_t idx) const;
            Path operator+(const Path &other) const;
            bool operator==(const Path &other) const;
            std::byte at(std::size_t idx) const;

            bool StartsWith(const Path &other) const;
            Path *Consume(std::size_t amount);
            Path CommonPrefix(const Path &other) const;

            // Methods used by sszpp. NO hash_tree_root METHOD PROVIDED
            constexpr std::size_t ssz_size() const noexcept { return 1 + size() / 2; }

            constexpr void serialize(ssz::ssz_iterator auto result) const {
                std::size_t nibblesLen = size();
                bool isOdd = (nibblesLen % 2 == 1);

                // If even size, we just insert empty byte at the beginning
                auto prefix = std::byte{0x00};

                // If odd, we put kOddFlag at the first nibble and the first element of Path after
                // it, so we could insert by full bytes afterwards
                if (isOdd) {
                    prefix = kOddFlag | at(0);
                }

                std::copy(static_cast<const std::byte *>(static_cast<const void *>(&prefix)),
                          static_cast<const std::byte *>(static_cast<const void *>(&prefix)) + 1,
                          result);
                ++result;

                for (std::size_t i = (isOdd ? 1 : 0); i < nibblesLen; i += 2) {
                    std::byte nextByte = (operator[](i) << 4) | operator[](i + 1);
                    std::copy(
                        static_cast<const std::byte *>(static_cast<const void *>(&nextByte)),
                        static_cast<const std::byte *>(static_cast<const void *>(&nextByte)) + 1,
                        result);
                    ++result;
                }
            }

            constexpr void deserialize(const std::ranges::sized_range auto &bytes) {
                bool isOddLen = (bytes.front() & kOddFlag) == kOddFlag;
                if (isOddLen) {
                    offset_ = 1;
                } else {
                    offset_ = 2;
                }

                data_.reserve(std::ranges::size(bytes));
                std::ranges::copy(bytes, std::back_inserter(data_));
            }

          private:
            Path ConstructFromPrefix(std::size_t length) const;

            static constexpr std::byte kOddFlag = std::byte{0x10};
            std::vector<std::byte> data_;
            std::size_t offset_ = 0;
        };

    }  // namespace mpt
}  // namespace core

#endif  // ZKEMV_FRAMEWORK_LIBS_NIL_CORE_INCLUDE_ZKEVM_FRAMEWORK_CORE_MPT_MPT_HPP_
