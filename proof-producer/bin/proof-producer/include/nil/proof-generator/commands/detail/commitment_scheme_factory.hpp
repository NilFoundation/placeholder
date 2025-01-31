#pragma once

#include <nil/proof-generator/types/type_system.hpp>


namespace nil {
    namespace proof_generator {

        template <typename CurveType, typename HashType>
        struct CommitmentSchemeFactory {
            using Types                  = TypeSystem<CurveType, HashType>;
            using LpcScheme              = typename Types::LpcScheme;
            using FriParams              = typename Types::FriParams;

        public:
            CommitmentSchemeFactory(PlaceholderConfig config):
                config_(config) {}
        
            std::shared_ptr<LpcScheme> make_lpc_scheme(uint32_t rows_amount) const {
                // Lambdas and grinding bits should be passed through preprocessor directives
                std::size_t table_rows_log = std::ceil(std::log2(rows_amount));

                return std::make_shared<LpcScheme>(LpcScheme(FriParams(1, table_rows_log, 
                    config_.lambda, config_.expand_factor, config_.grind!=0, config_.grind)));
            }

            const PlaceholderConfig config_;
        };
    } // namespace proof_generator
} // namespace nil