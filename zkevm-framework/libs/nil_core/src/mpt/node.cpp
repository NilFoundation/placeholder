#include "zkevm_framework/core/mpt/node.hpp"

#include <span>
#include <stdexcept>

namespace core {
    namespace mpt {

        PathHolder::PathHolder(Path path) : path(std::move(path)) {}

        ValueHolder::ValueHolder(const std::vector<std::byte>& value) { set_value(value); }

        const std::vector<std::byte>& ValueHolder::value() const { return value_.data(); }

        void ValueHolder::set_value(const std::vector<std::byte>& new_value) { value_ = new_value; }

        LeafNode::LeafNode(const Path& path, const std::vector<std::byte>& new_value)
            : PathHolder(path), ValueHolder(new_value) {}

        Bytes LeafNode::Encode() const {
            auto serialized = std::vector<std::byte>(ssz_size() + 1);
            serialized.front() = static_cast<std::byte>(NodeTypeFlag::kLeafNode);
            ssz::serialize(serialized.begin() + 1, *this);
            return serialized;
        }

        ExtensionNode::ExtensionNode(const Path& path, const Reference& next)
            : PathHolder(path), next_ref_(next) {}

        Bytes ExtensionNode::Encode() const {
            auto serialized = std::vector<std::byte>(ssz_size() + 1);
            serialized.front() = static_cast<std::byte>(NodeTypeFlag::kExtensionNode);
            ssz::serialize(serialized.begin() + 1, *this);
            return serialized;
        }

        const Reference& ExtensionNode::get_next_ref() const { return next_ref_.data(); }

        BranchNode::BranchNode(const std::array<Reference, kBranchesNum>& refs,
                               const std::vector<std::byte>& value)
            : ValueHolder(value) {
            for (const auto& branch : refs) {
                branches_.push_back(branch);
            }
        }

        Bytes BranchNode::Encode() const {
            auto serialized = std::vector<std::byte>(ssz_size() + 1);
            serialized.front() = static_cast<std::byte>(NodeTypeFlag::kBranchNode);
            ssz::serialize(serialized.begin() + 1, *this);
            return serialized;
        }

        std::array<Reference, kBranchesNum> BranchNode::get_branches() const {
            std::array<Reference, kBranchesNum> arr;
            const auto& branches_vec = branches_.data();
            for (std::size_t i = 0; i < branches_.size(); ++i) {
                arr[i] = branches_vec[i].data();
            }
            return arr;
        }

        void BranchNode::ClearBranch(std::byte nibble) {
            branches_[std::to_integer<uint8_t>(nibble)].data().clear();
        }

        void BranchNode::SetBranch(std::byte nibble, const std::vector<std::byte>& value) {
            branches_[std::to_integer<uint8_t>(nibble)] = value;
        }

        template<typename NodeType>
        Node DeserializeNode(const std::span<const std::byte>& bytes) {
            return ssz::deserialize<NodeType>(bytes);
        }

        Node DecodeNode(const Bytes& bytes) {
            if (bytes.empty()) {
                throw std::runtime_error("Empty byte array");
            }

            const auto type_flag = static_cast<NodeTypeFlag>(bytes.front());
            std::span<const std::byte> data_span(bytes.data() + 1, bytes.size() - 1);

            switch (type_flag) {
                case NodeTypeFlag::kLeafNode:
                    return DeserializeNode<LeafNode>(data_span);
                case NodeTypeFlag::kExtensionNode:
                    return DeserializeNode<ExtensionNode>(data_span);
                case NodeTypeFlag::kBranchNode:
                    return DeserializeNode<BranchNode>(data_span);
                default:
                    throw std::runtime_error("Unknown node type");
            }
        }

    }  // namespace mpt
}  // namespace core
