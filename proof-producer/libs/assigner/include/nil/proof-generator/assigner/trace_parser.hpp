#ifndef PROOF_GENERATOR_LIBS_ASSIGNER_TRACE_PARSER_HPP_
#define PROOF_GENERATOR_LIBS_ASSIGNER_TRACE_PARSER_HPP_

#include <optional>
#include <string>
#include <fstream>

#include <boost/filesystem.hpp>
#include <boost/log/trivial.hpp>

namespace nil {
    namespace proof_generator {
        class trace_parser {
        public:
            /// @brief Initialize file read iterators
            trace_parser(const boost::filesystem::path& trace_file_path):
                m_op_code_it(trace_file_path), m_stack_op_it(trace_file_path), m_mem_op_it(trace_file_path) {}

            /// @brief Read next stack operation
            std::optional<std::string> get_next_stack_op();

            /// @brief Read next stack operation
            std::optional<std::string> get_next_mem_op();

            /// @brief Read list of operations
            std::optional<std::string> get_op_codes();
        private:
            std::ifstream m_op_code_it;
            std::ifstream m_stack_op_it;
            std::ifstream m_mem_op_it;
        };

    } // proof_generator
} // nil

#endif  // PROOF_GENERATOR_LIBS_ASSIGNER_TRACE_PARSER_HPP_
