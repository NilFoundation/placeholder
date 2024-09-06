#ifndef ZKEMV_FRAMEWORK_LIBS_NIL_CORE_INCLUDE_ZKEVM_FRAMEWORK_CORE_MPT_MPT_HPP_
#define ZKEMV_FRAMEWORK_LIBS_NIL_CORE_INCLUDE_ZKEVM_FRAMEWORK_CORE_MPT_MPT_HPP_

#include <algorithm>
#include <cstdint>
#include <memory>
#include <unordered_map>
#include <vector>

#include "zkevm_framework/core/mpt/node.hpp"

namespace std {
    // To allow using vector of bytes as key in unordered_map
    template<>
    struct hash<vector<byte>> {
        size_t operator()(const vector<byte>& v) const {
            return hash<string_view>()(
                string_view(reinterpret_cast<const char*>(v.data()), v.size()));
        }
    };
}  // namespace std

namespace core {
    namespace mpt {

        namespace details {
            class GetHandler;
            class SetHandler;
            class DeleteHandler;
            struct DeleteResult;
        }  // namespace details

        class MerklePatriciaTrie {
          public:
            MerklePatriciaTrie();
            std::vector<std::byte> get(const std::vector<std::byte>& key) const;
            void set(const std::vector<std::byte>& key, const std::vector<std::byte>& value);
            void remove(const std::vector<std::byte>& key);

          protected:
            Node GetFromStorage(const Reference& ref) const;
            Reference PutToStorage(const Node& node);
            std::optional<std::vector<std::byte>> GetNode(const Reference& nodeRef,
                                                          Path& path) const;
            Reference SetNode(const Reference& nodeRef, Path& path,
                              const std::vector<std::byte>& value);
            details::DeleteResult DeleteNode(const Reference& nodeRef, const Path& path);

          private:
            static Path PathFromKey(const std::vector<std::byte>& key);
            static constexpr size_t kMaxRawKeyLen = 32;

            Reference root_;
            std::unordered_map<Reference, std::vector<std::byte>>
                nodes_;  // Better design is to use other external class for storage

            friend class details::GetHandler;
            friend class details::SetHandler;
            friend class details::DeleteHandler;
        };

    }  // namespace mpt
}  // namespace core

#endif  // ZKEMV_FRAMEWORK_LIBS_NIL_CORE_INCLUDE_ZKEVM_FRAMEWORK_CORE_MPT_MPT_HPP_
