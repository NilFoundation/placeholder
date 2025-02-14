#pragma once

#include <optional>

#include <boost/filesystem.hpp>
#include <boost/log/trivial.hpp>

#include <nil/proof-generator/types/type_system.hpp>
#include <nil/proof-generator/file_operations.hpp>
#include <nil/proof-generator/marshalling_utils.hpp>

#include <nil/crypto3/marshalling/math/types/polynomial.hpp>

namespace nil {
    namespace proof_producer {

        template <typename CurveType, typename HashType>
        struct PolynomialIO {
            using Types      = TypeSystem<CurveType, HashType>;
            using TTypeBase  = typename Types::TTypeBase;
            using Endianness = typename Types::Endianness;

            // NOTE: PolynomialType is not required to match Types::polynomial_type
            template <typename PolynomialType = Types::polynomial_type>
            static std::optional<PolynomialType> read_poly_from_file(const boost::filesystem::path &input_file) {

                namespace marshalling_types = nil::crypto3::marshalling::types;
                using polynomial_marshalling_type = marshalling_types::polynomial<
                    TTypeBase, PolynomialType>::type;

                if (!can_read_from_file(input_file.string())) {
                    BOOST_LOG_TRIVIAL(error) << "Can't read file " << input_file;
                    return std::nullopt;
                }

                auto marshalled_poly = detail::decode_marshalling_from_file<polynomial_marshalling_type>(
                    input_file);

                if (!marshalled_poly) {
                    BOOST_LOG_TRIVIAL(error) << "Problem with de-marshalling a polynomial read from a file" << input_file;
                    return std::nullopt;
                }

                return nil::crypto3::marshalling::types::make_polynomial<Endianness, PolynomialType>(marshalled_poly.value());
            }

            // NOTE: PolynomialType is not required to match Types::polynomial_type
            template <typename PolynomialType = Types::polynomial_type>
            static bool save_poly_to_file(const PolynomialType& poly, const boost::filesystem::path &output_file)
            {
                namespace marshalling_types = nil::crypto3::marshalling::types;

                using polynomial_marshalling_type = typename marshalling_types::polynomial<
                    TTypeBase, PolynomialType>::type;

                BOOST_LOG_TRIVIAL(info) << "Writing polynomial to " << output_file;

                polynomial_marshalling_type marshalled_poly = marshalling_types::fill_polynomial<Endianness, PolynomialType>(poly);

                return detail::encode_marshalling_to_file<polynomial_marshalling_type>(
                    output_file, marshalled_poly);
            }
        };

    } // namespace proof_producer
} // namespace nil
