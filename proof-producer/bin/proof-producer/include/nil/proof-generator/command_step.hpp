#pragma once

#include <memory>
#include <new>
#include <optional>
#include <queue>
#include <stdexcept>
#include <string>
#include <utility>
#include <format>
#include <concepts>

#include <boost/log/trivial.hpp>


namespace nil {

    namespace proof_producer {

        enum class ResultCode: uint8_t {
            Success = 0,
            IOError = 10,        // cannot access some of input files
            InvalidInput = 20,   // input files are inconsistent or malformed
            ProverError = 30,    // some logical error from proof system
            OutOfMemory = 40,    // managed memory allocation failure
            UnknownError = 0xFF,
        };

        inline constexpr const char* result_code_to_string(ResultCode rc) {
            switch (rc) {
                case ResultCode::Success:
                    return "Success";
                case ResultCode::IOError:
                    return "IOError";
                case ResultCode::InvalidInput:
                    return "InvalidInput";
                case ResultCode::ProverError:
                    return "ProverError";
                case ResultCode::OutOfMemory:
                    return "OutOfMemory";
                case ResultCode::UnknownError:
                    [[fallthrough]];
                default:
                    return "UnknownError";
            }
        }

        class CommandResult {

        private:
            ResultCode result_{ResultCode::UnknownError};
            std::optional<std::string> error_message_;

            constexpr explicit CommandResult() noexcept: result_(ResultCode::Success) {}
            explicit CommandResult(ResultCode rc, std::string error_message):
                result_(rc),
                error_message_(std::move(error_message))
            {}

        public:
            constexpr bool succeeded() const noexcept {
                return result_ == ResultCode::Success;
            }

            constexpr ResultCode result_code() const noexcept {
                return result_;
            }

            std::string error_message() const {
                if (succeeded()) {
                    return "";
                }

                return std::format("result_code={}({}): {}",
                    static_cast<uint8_t>(result_),
                    result_code_to_string(result_),
                    error_message_.value_or("no description")
                );
            }

            constexpr static CommandResult Ok() noexcept {
                return CommandResult();
            }

            template <typename... Args>
            static CommandResult Error(ResultCode rc, std::format_string<Args...> _fmt, Args&&... args) {
                return CommandResult(rc, std::format(_fmt, std::forward<Args>(args)...));
            }

            // Use this function only when it is not possible to provide a specific error code
            template <typename... Args>
            static CommandResult UnknownError(std::format_string<Args...> _fmt, Args&&... args) {
                return Error(ResultCode::UnknownError, _fmt, std::forward<Args>(args)...);
            }
        };

        // basic interface for a command step
        // non-copyable as it is designed to be used only as part of a command chain
        // each step should keep pointers to the resources it needs and accept them (or their providers) in the constructor
        class command_step {
        public:
            virtual CommandResult execute() = 0;
            virtual ~command_step() = default;

            command_step() = default;
            command_step(const command_step&) = delete;
            command_step& operator=(const command_step&) = delete;
            command_step(command_step&&) = default;
            command_step& operator=(command_step&&) = default;
        };


        // a chain of command steps to be executed sequentially
        // each step is executed in the queue order and is popped from the queue after execution and releases its resources
        // the chain is considered failed if any of the steps fails
        // includes exeption wrappers and meant to be used as a top-level command (however, it can be used as a step in another chain)
        class command_chain: public command_step {

        public:
            CommandResult execute() override final {
                int stage{1};
                int total_stages = steps_.size();
                CommandResult chain_res = CommandResult::Ok();
                try {
                    while (!steps_.empty()) {
                        auto const res = steps_.front()->execute();
                        if (!res.succeeded())
                        {
                            chain_res = res;
                            break;
                        }
                        steps_.pop();
                        stage++;
                    }
                }
                catch (std::logic_error const& e) {
                    chain_res = CommandResult::Error(ResultCode::ProverError, "caught logic error during command execution: {}", e.what());
                }
                catch (std::bad_alloc const& e) {
                    chain_res = CommandResult::Error(ResultCode::OutOfMemory, "allocation failure: {}", e.what());
                }
                catch (std::exception const& e) {
                    chain_res = CommandResult::UnknownError("unknown exception: {}", e.what());
                }

                if (!chain_res.succeeded()) {
                    BOOST_LOG_TRIVIAL(error) << "command failed on stage " << stage << " of " << total_stages << ": " << chain_res.error_message();
                    return chain_res;
                }

                return chain_res;
            }

        protected:
            // returns reference to the pushed step (non-owning, ownership is guaranteed by the step queue)
            template <typename Step, typename... Args>
                requires (std::derived_from<Step, command_step> && std::constructible_from<Step, Args...>)
            Step& add_step(Args&&... args) {
                BOOST_LOG_TRIVIAL(trace) << "adding " << steps_.size() + 1 << " step: " << __PRETTY_FUNCTION__;
                std::unique_ptr<command_step>& pushed = steps_.emplace(std::make_unique<Step>(std::forward<Args>(args)...));
                return dynamic_cast<Step&>(*pushed); // safe here because we know that we just pushed exactly this type
            }

        private:
            std::queue<std::unique_ptr<command_step>> steps_;
        };

    } // namespace proof_producer
} // namespace nil
