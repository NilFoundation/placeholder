#ifndef PROOF_GENERATOR_LIBS_ASSIGNER_OPTIONS_HPP_
#define PROOF_GENERATOR_LIBS_ASSIGNER_OPTIONS_HPP_

namespace nil {
    namespace proof_generator {

        struct AssignerOptions {
            bool ignore_index_mismatch{};

            uint64_t get_base_index(uint64_t in) const noexcept {
                if (this->ignore_index_mismatch) {
                    return 0;
                }
                return in;
            }
        };


    } // proof_generator
} // namespace nil

#endif // PROOF_GENERATOR_LIBS_ASSIGNER_OPTIONS_HPP_
