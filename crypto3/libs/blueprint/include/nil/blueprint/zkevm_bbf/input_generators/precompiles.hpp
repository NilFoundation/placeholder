//---------------------------------------------------------------------------//
// Copyright (c) 2025 Alexander Vasilyev <mizabrik@nil.foundation>
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

#ifndef NIL_BLUEPRINT_ZKEVM_INPUT_GENERATORS_PRECOMPILES_
#define NIL_BLUEPRINT_ZKEVM_INPUT_GENERATORS_PRECOMPILES_

#include <bit>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <stdexcept>
#include <vector>

#include <boost/log/trivial.hpp>
#include <boost/multiprecision/cpp_int.hpp>

#include "nil/blueprint/zkevm_bbf/types/zkevm_word.hpp"
#include "nil/crypto3/algebra/algorithms/pair.hpp"
#include "nil/crypto3/algebra/curves/alt_bn128.hpp"
#include "nil/crypto3/algebra/curves/bls12.hpp"
#include "nil/crypto3/algebra/curves/secp_k1.hpp"
#include "nil/crypto3/algebra/pairing/alt_bn128.hpp"
#include "nil/crypto3/algebra/pairing/bls12.hpp"
#include "nil/crypto3/hash/keccak.hpp"
#include "nil/crypto3/hash/sha2.hpp"
#include "nil/crypto3/multiprecision/big_uint.hpp"
#include "nil/crypto3/zk/commitments/polynomial/kzg.hpp"

namespace nil::blueprint::bbf {

#define ZKEVM_PRECOMPILE_LIST(X) \
    X(kEcRecover, 0x01)          \
    X(kSha2, 0x02)               \
    X(kRipemd160, 0x03)          \
    X(kIdentity, 0x04)           \
    X(kModexp, 0x05)             \
    X(kEcAdd, 0x06)              \
    X(kEcMul, 0x07)              \
    X(kEcPairing, 0x08)          \
    X(kBlake2f, 0x09)            \
    X(kPointEvaluation, 0x0a)

    // TODO: implement RIPEMD-160 and BLAKE2 compression function

    enum class Precompile : size_t {
#define ZKEVM_PRECOMPILE_ENUM(name, address) name = address,
        ZKEVM_PRECOMPILE_LIST(ZKEVM_PRECOMPILE_ENUM)
#undef ZKEVM_PRECOMPILE_ENUM
    };

    struct PrecompileResult {
        bool success;
        size_t gas_used;
        std::vector<uint8_t> data;
    };

    template<Precompile precompile>
    PrecompileResult evaluate_precompile(size_t gas, std::span<const uint8_t> input) {
        BOOST_LOG_TRIVIAL(error) << "precompile 0x" << std::hex << size_t(precompile)
                                 << std::dec << " not implemented" << std::endl;
        throw std::logic_error{"precompile not implemented"};
    }

    namespace detail {

        using nil::crypto3::multiprecision::big_uint;

        // NOTE: EVM spec mandates "infinite length by appending zeroes as required"
        // for input data, hence all the padding staff below.

        template<size_t N>
        std::array<uint8_t, N> read_bytes(std::span<const uint8_t> &input) {
            std::array<uint8_t, N> result{};

            size_t n_read = std::min(N, input.size());
            std::memcpy(result.data(), input.data(), n_read);
            input = input.subspan(n_read);
            return result;
        }

        template<size_t Bits>
        big_uint<Bits> read_big_uint(std::span<const uint8_t> &input) {
            big_uint<Bits> result;
            auto bytes = read_bytes<(Bits + 7) / 8>(input);
            result.import_bits(bytes.begin(), bytes.end());
            return result;
        }

        inline zkevm_word_type read_zkevm_word(std::span<const uint8_t> &input) {
            return read_big_uint<256>(input);
        }

        // TODO: is it ok to just throw here?
        inline size_t read_size_t(std::span<const uint8_t> &input) {
            auto word = read_zkevm_word(input);
            if (word > std::numeric_limits<size_t>::max())
                throw std::range_error("precompile argument is too big");
            return size_t(word);
        }

        inline boost::multiprecision::cpp_int read_cpp_int(
            std::span<const uint8_t> &input, size_t size) {
            using namespace boost::multiprecision;

            size_t padding = input.size() < size ? size - input.size() : 0;

            cpp_int result;
            import_bits(result, input.begin(), input.begin() + size - padding);
            result <<= 8 * padding;

            input = input.subspan(size - padding);
            return result;
        }

        std::optional<crypto3::algebra::curves::alt_bn128_254::g1_type<>::value_type>
        read_alt_bn128_g1_point(std::span<const uint8_t> &input) {
            using Curve = crypto3::algebra::curves::alt_bn128_254;
            using Field = Curve::base_field_type;
            using Point = Curve::g1_type<>::value_type;

            std::array<Field::value_type, 2> coordinates;
            for (auto &c : coordinates) {
                auto value = read_zkevm_word(input);
                if (value >= Curve::base_field_type::modulus) return std::nullopt;
                c = Field::value_type(value);
            }

            if (coordinates[0].is_zero() && coordinates[1].is_zero())
                return Point::zero();

            Point point(coordinates[0], coordinates[1]);
            if (!point.is_well_formed()) return std::nullopt;

            return point;
        }

        std::optional<crypto3::algebra::curves::alt_bn128_254::g2_type<>::value_type>
        read_alt_bn128_g2_point(std::span<const uint8_t> &input) {
            using Curve = crypto3::algebra::curves::alt_bn128_254;
            using BaseField = Curve::base_field_type;
            using Field = Curve::g2_type<>::field_type;
            using Point = Curve::g2_type<>::value_type;
            using crypto3::algebra::curves::detail::subgroup_check;

            std::array<Field::value_type, 2> coordinates;
            for (auto &c : coordinates) {
                auto a = read_zkevm_word(input);
                auto b = read_zkevm_word(input);

                if (a >= BaseField::modulus || b >= BaseField::modulus)
                    return std::nullopt;
                c = Field::value_type(b, a);
            }

            if (coordinates[0].is_zero() && coordinates[1].is_zero())
                return Point::zero();

            Point p(coordinates[0], coordinates[1]);
            if (!p.is_well_formed() || !subgroup_check(p)) return std::nullopt;
            return p;
        }

        // https://github.com/supranational/blst/blob/master/README.md#serialization-format
        std::optional<crypto3::algebra::curves::bls12_381::g1_type<>::value_type>
        read_kzg_g1_point(std::span<const uint8_t> &input) {
            using crypto3::algebra::curves::bls12_381;
            using BaseField = bls12_381::base_field_type;
            using Params = bls12_381::g1_type<>::params_type;
            using Point = bls12_381::g1_type<>::value_type;
            using crypto3::algebra::curves::detail::subgroup_check;

            // For KZG, input is guaranteed to have proper size
            if (input.size() < 48)
                throw std::logic_error("insufficient input size for KZG precompile");

            auto raw_x = read_big_uint<384>(input);

            // first bit: is compressed
            if (!raw_x.bit_test(383)) return std::nullopt;
            raw_x.bit_unset(383);

            // second bit: is point at infinity (everything else must be 0);
            // it is permmitted to be used in KZG by EIP!
            if (raw_x.bit_test(382)) {
                raw_x.bit_unset(382);
                if (!raw_x.is_zero()) return std::nullopt;
                return Point::zero();
            }

            // third bit: pick bigger root for y
            bool pick_bigger_root = raw_x.bit_test(381);
            raw_x.bit_unset(381);

            if (raw_x >= BaseField::modulus) return std::nullopt;
            BaseField::value_type x = raw_x;

            auto y_square = x * x * x + Params::b;  // a = 0
            if (!y_square.is_square()) return std::nullopt;

            auto y1 = y_square.sqrt();
            auto y2 = -y1;
            bool y1_is_bigger = y1.to_integral() > y2.to_integral();
            auto y = (y1_is_bigger == pick_bigger_root) ? y1 : y2;

            Point p(x, y);
            if (!subgroup_check(p)) return std::nullopt;
            return p;
        }

    }  // namespace detail

    template<>
    PrecompileResult evaluate_precompile<Precompile::kEcRecover>(
        size_t gas, std::span<const uint8_t> input) {
        using namespace detail;
        using Keccak = crypto3::hashes::keccak_1600<256>;
        using crypto3::algebra::curves::secp256k1;
        using Params = secp256k1::g1_type<>::params_type;
        using Field = secp256k1::base_field_type::value_type;
        using Point = secp256k1::g1_type<>::value_type;
        using Scalar = secp256k1::scalar_field_type::value_type;

        const auto n = secp256k1::scalar_field_type::modulus;

        size_t gas_fee = 3000;
        if (gas < gas_fee) return {0, 0, {}};

        auto hash = read_zkevm_word(input);
        auto v = read_zkevm_word(input);
        auto r = read_zkevm_word(input);
        auto s = read_zkevm_word(input);

        if (v != 27 && v != 28 || r == 0 || r >= n || s == 0 || s >= n)
            return {0, gas_fee, {}};

        // Calculate a curve point R = (x, y) where x is one of r, r + n, r + 2n, etc
        // (provided x is not too large for the field of the curve)
        // NOTE: py-evm and evmnone check only x = r.
        Field x = r;
        auto y_square = x * x * x + Params::b;  // a = 0
        if (!y_square.is_square()) return {0, gas_fee, {}};
        auto y = y_square.sqrt();
        auto y_parity = y.to_integral() & 1;
        auto parity = (v - 27) & 1;
        Point R(x, y_parity == parity ? y : -y);

        // Let z be the L_n leftmost bits of hash: n is 256 bit, so z = hash
        // Calculate u1 = -z * inv(r) and u2 = s * inv(r)
        auto u1 = -Scalar(hash) * Scalar(r).inversed();
        auto u2 = Scalar(s) * Scalar(r).inversed();

        // Calculate the curve point Q = u1 * G + u2 * R
        auto Q = (u1 * Point::one() + u2 * R).to_affine();
        auto Q_x = Q.X.to_integral();
        auto Q_y = Q.Y.to_integral();

        std::vector<uint8_t> Q_data(64);
        for (int i = 0; i < 32; ++i) {
            Q_data[31 - i] = uint8_t(Q_x & 0xFF);
            Q_x >>= 8;

            Q_data[63 - i] = uint8_t(Q_y & 0xFF);
            Q_y >>= 8;
        }

        std::array<uint8_t, 32> Q_hash = crypto3::hash<Keccak>(Q_data);
        std::vector<uint8_t> result(32);
        std::memcpy(result.data() + 12, Q_hash.data() + 12, 20);

        return {1, gas_fee, std::move(result)};
    }

    template<>
    PrecompileResult evaluate_precompile<Precompile::kSha2>(
        size_t gas, std::span<const uint8_t> input) {
        using namespace nil::crypto3;

        size_t data_word_size = (input.size() + 31) / 32;
        size_t gas_fee = 60 + 12 * data_word_size;
        if (gas < gas_fee) return {0, 0, {}};

        PrecompileResult result{1, gas_fee};
        // TODO: span<const T> fails is_range check for shorter syntax
        hash<hashes::sha2<256>>(input.begin(), input.end(),
                                std::back_inserter(result.data));
        return result;
    }

    template<>
    PrecompileResult evaluate_precompile<Precompile::kIdentity>(
        size_t gas, std::span<const uint8_t> input) {
        size_t data_word_size = (input.size() + 31) / 32;
        size_t gas_fee = 15 + 3 * data_word_size;
        if (gas < gas_fee) return {0, 0, {}};

        return {1, gas_fee, {input.begin(), input.end()}};
    }

    template<>
    PrecompileResult evaluate_precompile<Precompile::kModexp>(
        size_t gas, std::span<const uint8_t> input) {
        using namespace detail;

        auto b_size = read_size_t(input);
        auto e_size = read_size_t(input);
        auto m_size = read_size_t(input);

        auto gas_f = [](size_t x) {
            size_t tmp = (x + 7) / 8;
            return tmp * tmp;
        };

        size_t e_bits = e_size > 32 ? 8 * (e_size - 32) : 0;
        for (size_t i = 0; i < std::min(e_size, size_t{32}); ++i) {
            uint8_t e_byte = b_size + i < input.size() ? input[b_size + i] : 0;
            if (e_byte == 0) continue;

            e_bits += (std::bit_width(e_byte) - 1) + 8 * (e_size - i - 1);
            break;
        }

        size_t dynamic_gas =
            gas_f(std::max(b_size, m_size)) * std::max(e_bits, size_t{1}) / 3;
        size_t gas_fee = std::max(dynamic_gas, size_t{200});
        if (gas < gas_fee) return {0, 0, {}};

        auto b = read_cpp_int(input, b_size);
        auto e = read_cpp_int(input, e_size);
        auto m = read_cpp_int(input, m_size);

        boost::multiprecision::cpp_int o = boost::multiprecision::powm(b, e, m);

        std::vector<uint8_t> output(m_size);
        boost::multiprecision::export_bits(o, output.rbegin(), 8,
                                           /* big_endian = */ false);
        return {1, gas_fee, std::move(output)};
    }

    // EIP-196
    template<>
    PrecompileResult evaluate_precompile<Precompile::kEcAdd>(
        size_t gas, std::span<const uint8_t> input) {
        using namespace detail;
        using Curve = crypto3::algebra::curves::alt_bn128_254;

        size_t gas_fee = 150;
        if (gas < gas_fee) return {0, 0, {}};

        auto x = read_alt_bn128_g1_point(input);
        auto y = read_alt_bn128_g1_point(input);
        if (!x || !y) return {0, gas_fee, {}};

        auto result = (*x + *y).to_affine();
        auto result_x = result.X.to_integral();
        auto result_y = result.Y.to_integral();

        std::vector<uint8_t> data(64);
        for (int i = 0; i < 32; ++i) {
            data[31 - i] = uint8_t(result_x & 0xFF);
            result_x >>= 8;

            data[63 - i] = uint8_t(result_y & 0xFF);
            result_y >>= 8;
        }

        return {1, gas_fee, std::move(data)};
    }

    // EIP-196
    template<>
    PrecompileResult evaluate_precompile<Precompile::kEcMul>(
        size_t gas, std::span<const uint8_t> input) {
        using namespace detail;
        using Curve = crypto3::algebra::curves::alt_bn128_254;

        size_t gas_fee = 6000;
        if (gas < 6000) return {0, 0, {}};

        auto x = read_alt_bn128_g1_point(input);
        if (!x) return {0, gas_fee, {}};

        // Generic big_mod (used for multiplication by scalar later) asserts that
        // the value is less than modulus, so let's take remainder by ourselves
        // to be on the safe side.
        auto s = read_zkevm_word(input) % Curve::scalar_field_type::modulus;

        auto result = (*x * s).to_affine();
        auto result_x = result.X.to_integral();
        auto result_y = result.Y.to_integral();

        std::vector<uint8_t> data(64);
        for (int i = 0; i < 32; ++i) {
            data[31 - i] = uint8_t(result_x & 0xFF);
            result_x >>= 8;

            data[63 - i] = uint8_t(result_y & 0xFF);
            result_y >>= 8;
        }

        return {1, gas_fee, std::move(data)};
    }

    // EIP-197
    template<>
    PrecompileResult evaluate_precompile<Precompile::kEcPairing>(
        size_t gas, std::span<const uint8_t> input) {
        using namespace detail;
        namespace algebra = crypto3::algebra;
        using Curve = algebra::curves::alt_bn128_254;

        if (input.size() % 192 != 0) return {0, 0, {}};

        size_t k = input.size() / 192;
        size_t gas_fee = 45000 + 34000 * k;
        if (gas < gas_fee) return {0, 0, {}};

        auto accum = Curve::gt_type::value_type::one();
        for (size_t i = 0; i < k; ++i) {
            auto a = read_alt_bn128_g1_point(input);
            auto b = read_alt_bn128_g2_point(input);
            if (!a || !b) return {0, gas_fee, {}};

            accum *= algebra::pair<Curve>(*a, *b);
        }

        auto result = algebra::final_exponentiation<Curve>(accum);

        std::vector<uint8_t> data(32, 0);
        data.back() = result && result->is_one();
        return {1, gas_fee, std::move(data)};
    }

    // EIP-4844
    template<>
    PrecompileResult evaluate_precompile<Precompile::kPointEvaluation>(
        size_t gas, std::span<const uint8_t> input) {
        using namespace detail;
        using namespace crypto3;
        using Curve = algebra::curves::bls12<381>;
        using Point = Curve::g1_type<>::value_type;
        using Field = Curve::base_field_type;
        using Kzg = zk::commitments::kzg<Curve>;
        using zk::algorithms::verify_eval;

        const zkevm_word_type kFieldElementsPerBlob = 4096;
        const zkevm_word_type kBlsModulus = Curve::scalar_field_type::modulus;
        const uint8_t kHashVersion = 0x01;

        size_t gas_fee = 50000;
        if (gas < gas_fee) return {0, 0, {}};

        if (input.size() != 192)  // Explicitly checked in EIP
            return {0, gas_fee, {}};

        auto versioned_hash = read_bytes<32>(input);

        auto z = read_zkevm_word(input);
        auto y = read_zkevm_word(input);
        if (z >= Field::modulus || y >= Field::modulus) return {0, gas_fee, {}};

        std::array<uint8_t, 32> commitment_hash =
            hash<hashes::sha2<256>>(input.data(), input.data() + 48);
        commitment_hash[0] = kHashVersion;
        if (versioned_hash != commitment_hash) return {0, gas_fee, {}};

        auto commitment = read_kzg_g1_point(input);
        auto proof = read_kzg_g1_point(input);
        if (!commitment || !proof) return {0, gas_fee, {}};

        static const Kzg::params_type params{
            {},
            {{0x185cbfee53492714734429b7b38608e23926c911cceceac9a36851477ba4c60b087041de621000edc98edada20c1def2_big_uint381,
              0x15bfd7dd8cdeb128843bc287230af38926187075cbfbefa81009a2ce615ac53d2914e5870cb452d2afaaab24f3499f72_big_uint381},
             {0x014353bdb96b626dd7d5ee8599d1fca2131569490e28de18e82451a496a9c9794ce26d105941f383ee689bfbbb832a99_big_uint381,
              0x1666c54b0a32529503432fcae0181b4bef79de09fc63671fda5ed1ba9bfa07899495346f3d7ac9cd23048ef30d0a154f_big_uint381}}};

        if (!verify_eval<Kzg>(params, *proof, {*commitment, z, y}))
            return {0, gas_fee, {}};

        std::vector<uint8_t> result(64);
        kFieldElementsPerBlob.export_bits(result.rbegin() + 32, 8, false);
        kBlsModulus.export_bits(result.rbegin(), 8, false);

        return {1, gas_fee, std::move(result)};
    }

    inline PrecompileResult evaluate_precompile(Precompile precompile, size_t gas,
                                                std::span<const uint8_t> input) {
        using enum Precompile;

#define ZKEVM_PRECOMPILE_EVALUATE(name, address) \
    case name:                                   \
        return evaluate_precompile<name>(gas, input);

        switch (precompile) {
            ZKEVM_PRECOMPILE_LIST(ZKEVM_PRECOMPILE_EVALUATE)

            default:
                BOOST_LOG_TRIVIAL(error) << "unknown precompile 0x" << std::hex
                                         << size_t(precompile) << std::dec << std::endl;
                throw std::invalid_argument("address is not a precompile");
        }

#undef ZKEVM_PRECOMPILE_EVALUATE
    }

#undef ZKEVM_PRECOMPILE_LIST

}  // namespace nil::blueprint::bbf

#endif  // NIL_BLUEPRINT_ZKEVM_INPUT_GENERATORS_PRECOMPILES_
