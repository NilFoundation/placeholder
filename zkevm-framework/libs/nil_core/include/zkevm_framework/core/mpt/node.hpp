#ifndef ZKEMV_FRAMEWORK_LIBS_NIL_CORE_INCLUDE_ZKEVM_FRAMEWORK_CORE_MPT_NODE_HPP_
#define ZKEMV_FRAMEWORK_LIBS_NIL_CORE_INCLUDE_ZKEVM_FRAMEWORK_CORE_MPT_NODE_HPP_

#include <cstdint>
#include <ssz++.hpp>
#include <vector>

#include "zkevm_framework/core/mpt/path.hpp"

namespace core {
    namespace mpt {

        constexpr size_t kBranchesNum = 16;

        using Bytes = std::vector<std::byte>;
        using Reference = Bytes;

        enum class NodeTypeFlag : std::uint8_t {
            kLeafNode = 0,
            kExtensionNode = 1,
            kBranchNode = 2
        };

        class Serializable {
          public:
            virtual ~Serializable() = default;
            virtual Bytes Encode() const = 0;
        };

        class NodeBase : public ssz::ssz_variable_size_container, public Serializable {};

        class PathHolder {
          public:
            PathHolder() = default;
            explicit PathHolder(Path path);

            Path path;
        };

        class ValueHolder {
          public:
            ValueHolder() = default;
            explicit ValueHolder(const std::vector<std::byte>& value);

            const std::vector<std::byte>& value() const;
            void set_value(const std::vector<std::byte>& new_value);

          protected:
            ssz::list<std::byte, 100000000> value_;
        };

        class LeafNode : public NodeBase, public ValueHolder, public PathHolder {
          public:
            LeafNode() = default;
            LeafNode(const Path& path, const std::vector<std::byte>& new_value);

            Bytes Encode() const override;

            SSZ_CONT(path, value_)
        };

        class ExtensionNode : public NodeBase, public PathHolder {
          public:
            ExtensionNode() = default;
            ExtensionNode(const Path& path, const Reference& next);

            Bytes Encode() const override;
            const Reference& get_next_ref() const;

            SSZ_CONT(path, next_ref_)

          private:
            ssz::list<std::byte, 1000> next_ref_;
        };

        class BranchNode : public ValueHolder, public NodeBase {
          public:
            BranchNode() = default;
            BranchNode(const std::array<Reference, kBranchesNum>& refs,
                       const std::vector<std::byte>& value);

            Bytes Encode() const override;
            std::array<Reference, kBranchesNum> get_branches() const;
            void ClearBranch(std::byte nibble);
            void SetBranch(std::byte nibble, const std::vector<std::byte>& value);

            SSZ_CONT(branches_, value_)

          private:
            ssz::list<ssz::list<std::byte, 1000>, kBranchesNum> branches_;
        };

        using Node = std::variant<LeafNode, ExtensionNode, BranchNode>;

        Node DecodeNode(const Bytes& bytes);

    }  // namespace mpt
}  // namespace core

#endif  // ZKEMV_FRAMEWORK_LIBS_NIL_CORE_INCLUDE_ZKEVM_FRAMEWORK_CORE_MPT_NODE_HPP_
