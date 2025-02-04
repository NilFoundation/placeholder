#ifndef PROOF_GENERATOR_LIBS_ASSIGNER_OPTIONS_HPP_
#define PROOF_GENERATOR_LIBS_ASSIGNER_OPTIONS_HPP_

#include <nil/proof-generator/preset/limits.hpp>

namespace nil {
    namespace proof_producer {

        struct AssignerOptions {
            AssignerOptions(bool ignore, const CircuitsLimits& limits):
                ignore_index_mismatch(ignore),
                circuits_limits(limits) {}
            bool ignore_index_mismatch{};
            CircuitsLimits circuits_limits{};
       };


    } // proof_producer
} // namespace nil

#endif // PROOF_GENERATOR_LIBS_ASSIGNER_OPTIONS_HPP_
