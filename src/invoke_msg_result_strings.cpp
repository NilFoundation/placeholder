#include <nil/actor/invoke_message_result.hpp>

#include <string>

namespace nil {
    namespace actor {

        std::string to_string(invoke_message_result x) {
            switch (x) {
                default:
                    return "???";
                case invoke_message_result::consumed:
                    return "consumed";
                case invoke_message_result::skipped:
                    return "skipped";
                case invoke_message_result::dropped:
                    return "dropped";
            };
        }

    }    // namespace actor
}    // namespace nil
