//---------------------------------------------------------------------------//
// Copyright (c) Nil Foundation and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.
//---------------------------------------------------------------------------//

#ifndef EVM_ASSIGNER_LIB_ASSIGNER_INCLUDE_ZKEVM_WORD_HPP_
#define EVM_ASSIGNER_LIB_ASSIGNER_INCLUDE_ZKEVM_WORD_HPP_

#include <evmc.hpp>
#include <intx/intx.hpp>
#include <ethash/keccak.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>
#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>

namespace nil {
    namespace evm_assigner {

        using Endianness = nil::marshalling::option::big_endian;
        using TTypeBase = nil::marshalling::field_type<Endianness>;

        template <typename BlueprintFieldType>
        struct zkevm_word {
            using column_type_t = typename crypto3::zk::snark::plonk_column<BlueprintFieldType>;
            using value_type = intx::uint256;
            static constexpr uint64_t size = sizeof(value_type);
            // constructors
            zkevm_word() {
                value = 0;
            }

            zkevm_word(int v) {
                value = v;
            }

            zkevm_word(int64_t v) {
                value = v;
            }

            zkevm_word(uint64_t v) {
                value = v;
            }

            zkevm_word(const intx::uint256& v) {
                value = v;
            }

            zkevm_word(const evmc::uint256be& v) {
                value = intx::be::load<intx::uint256>(v);
            }

            zkevm_word(const evmc::address& addr) {
                value = intx::be::load<intx::uint256>(addr);
            }

            zkevm_word(const ethash::hash256& hash) {
                value = intx::be::load<intx::uint256>(hash);
            }

            zkevm_word(const uint8_t* data, size_t len) {
                assert(len <= 32);
                // copy data into zero-padded memory
                std::vector<uint8_t> bytes(32, 0);
                for (unsigned i = 0; i < len; ++i) {
                    bytes[32 - len + i] = data[i];
                }
                value = intx::be::unsafe::load<intx::uint256>(bytes.data());
            }

            // operators
            zkevm_word<BlueprintFieldType> operator+(const zkevm_word<BlueprintFieldType>& other) const {
                return zkevm_word<BlueprintFieldType>(value + other.value);
            }

            zkevm_word<BlueprintFieldType> operator-(const zkevm_word<BlueprintFieldType>& other) const {
                return zkevm_word<BlueprintFieldType>(value - other.value);
            }

            zkevm_word<BlueprintFieldType> operator*(const zkevm_word<BlueprintFieldType>& other) const {
                return zkevm_word<BlueprintFieldType>(value * other.value);
            }

            zkevm_word<BlueprintFieldType> operator/(const zkevm_word<BlueprintFieldType>& other) const {
                return zkevm_word<BlueprintFieldType>(value / other.value);
            }

            zkevm_word<BlueprintFieldType> operator%(const zkevm_word<BlueprintFieldType>& other) const {
                return zkevm_word<BlueprintFieldType>(value % other.value);
            }

            zkevm_word<BlueprintFieldType> sdiv(const zkevm_word<BlueprintFieldType>& other) const {
                return other.value != 0 ? intx::sdivrem(value, other.value).quot : 0;
            }

            zkevm_word<BlueprintFieldType> smod(const zkevm_word<BlueprintFieldType>& other) const {
                return other.value != 0 ? intx::sdivrem(value, other.value).rem : 0;
            }

            zkevm_word<BlueprintFieldType> addmod(const zkevm_word<BlueprintFieldType>& other, const zkevm_word<BlueprintFieldType>& m) const {
                return m != 0 ? intx::addmod(value, other.value, m.value) : 0;
            }

            zkevm_word<BlueprintFieldType> mulmod(const zkevm_word<BlueprintFieldType>& other, const zkevm_word<BlueprintFieldType>& m) const {
                return m != 0 ? intx::mulmod(value, other.value, m.value) : 0;
            }

            zkevm_word<BlueprintFieldType> exp(const zkevm_word<BlueprintFieldType>& e) const {
                return intx::exp(value, e.value);
            }

            unsigned count_significant_bytes() const {
                return intx::count_significant_bytes(value);
            }

            bool slt(const zkevm_word<BlueprintFieldType>& other) const {
                return intx::slt(value, other.value);
            }

            bool operator==(const zkevm_word<BlueprintFieldType>& other) const {
                return value == other.value;
            }

            bool operator!=(const zkevm_word<BlueprintFieldType>& other) const {
                return value != other.value;
            }

            bool operator!=(int v) const {
                return value != v;
            }

            bool operator<(const zkevm_word<BlueprintFieldType>& other) const {
                return value < other.value;
            }

            bool operator<(int v) const {
                return value < v;
            }

            zkevm_word<BlueprintFieldType> operator&(const zkevm_word<BlueprintFieldType>& other) const {
                return value & other.value;
            }

            typename BlueprintFieldType::integral_type operator&(const typename BlueprintFieldType::integral_type& other) const {
                typename BlueprintFieldType::integral_type val = value[0];
                typename BlueprintFieldType::integral_type lo = value[1];
                typename BlueprintFieldType::integral_type hi = value[2];
                typename BlueprintFieldType::integral_type h = value[3];
                val += lo << 64;
                val += hi << 64 * 2;
                val += h << 64 * 3;
                return val & other;
            }

            zkevm_word<BlueprintFieldType> operator|(const zkevm_word<BlueprintFieldType>& other) const {
                return value | other.value;
            }

            zkevm_word<BlueprintFieldType> operator^(const zkevm_word<BlueprintFieldType>& other) const {
                return value ^ other.value;
            }

            zkevm_word<BlueprintFieldType> operator~() const {
                return ~value;
            }

            zkevm_word<BlueprintFieldType> operator<<(const zkevm_word<BlueprintFieldType>& other) const {
                return value << other.value;
            }

            zkevm_word<BlueprintFieldType> operator>>(const zkevm_word<BlueprintFieldType>& other) const {
                return value >> other.value;
            }

            zkevm_word<BlueprintFieldType> operator<<(uint64_t v) const {
                return value << v;
            }

            zkevm_word<BlueprintFieldType> operator>>(uint64_t v) const {
                return value >> v;
            }

            // convertions
            uint64_t to_uint64(size_t i = 0) const {
                return static_cast<uint64_t>(value[i]);
            }

            const value_type &get_value() const
            {
                return value;
            }

            ethash::hash256 to_hash() const {
                return intx::be::store<ethash::hash256>(value);
            }

            evmc::address to_address() const {
                return intx::be::trunc<evmc::address>(value);
            }

            typename BlueprintFieldType::value_type to_field_as_address() const {
                typename BlueprintFieldType::integral_type res = value[0];
                typename BlueprintFieldType::integral_type lo = value[1];
                typename BlueprintFieldType::integral_type hi = value[2];
                res += lo << 64;
                res += hi << 128;
                return res;
            }

            evmc::uint256be to_uint256be() const {
                return intx::be::store<evmc::uint256be>(value);
            }

            //partial size_t
            void set_val(uint64_t v, size_t i) {
                value[i] = v;
            }

            // memory
            template<typename T> // uint8, uint16, uint32, uint64, intx::uint256
            void store(uint8_t* data) const {
                intx::be::unsafe::store(data, static_cast<T>(value));
            }

            void load_partial_data(const uint8_t* data, size_t len, size_t i) {
                switch (len) {
                    case 1:
                        value[i] = intx::be::unsafe::load<uint8_t>(data);
                        break;
                    case 2:
                        value[i] = intx::be::unsafe::load<uint16_t>(data);
                        break;
                    case 3:
                        value[i] = intx::be::unsafe::load<uint32_t>(data) >> 8;
                        break;
                    case 4:
                        value[i] = intx::be::unsafe::load<uint32_t>(data);
                        break;
                    case 5:
                    case 6:
                    case 7:
                    case 8:
                        value[i] = intx::be::unsafe::load<uint64_t>(data) >> (8 * (sizeof(uint64_t) - len));
                        break;
                };
            }

            typename BlueprintFieldType::value_type w_hi() const {
                typename BlueprintFieldType::integral_type res = value[3];
                res = res << 64;
                res += value[2];
                return res;
            }

            typename BlueprintFieldType::value_type w_lo() const {
                typename BlueprintFieldType::integral_type res = value[1];
                res = res << 64;
                res += value[0];
                return res;
            }

        private:
                intx::uint256 value;
        };

        template <typename BlueprintFieldType>
        std::ostream& operator<<(std::ostream& os, const zkevm_word<BlueprintFieldType>& obj){
            const auto word = obj.to_uint256be();
            for (uint8_t i = 0; i < 32; i++) {
                os << (int)word.bytes[i] << " ";
            }
            return os;
        }
    }     // namespace evm_assigner
}    // namespace nil
#endif    // EVM_ASSIGNER_LIB_ASSIGNER_INCLUDE_ZKEVM_WORD_HPP_
