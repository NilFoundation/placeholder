#include "zkevm_framework/core/mpt/mpt.hpp"

namespace core {
    namespace mpt {
        namespace details {

            template<class... Ts>
            struct overloaded : Ts... {
                using Ts::operator()...;
            };
            template<class... Ts>
            overloaded(Ts...) -> overloaded<Ts...>;

            class GetHandler {
              public:
                GetHandler(const MerklePatriciaTrie& mpt, Path& path) : mpt_(mpt), path_(path) {}

                std::optional<std::vector<std::byte>> operator()(const LeafNode& leaf) const {
                    if (leaf.path == path_) {
                        return leaf.value();
                    }
                    return std::nullopt;
                }

                std::optional<std::vector<std::byte>> operator()(
                    const ExtensionNode& extension_node) const {
                    if (path_.size() >= extension_node.path.size() &&
                        path_.StartsWith(extension_node.path)) {
                        path_.Consume(extension_node.path.size());
                        return mpt_.GetNode(extension_node.get_next_ref(), path_);
                    }
                    return std::nullopt;
                }

                std::optional<std::vector<std::byte>> operator()(
                    const BranchNode& branch_node) const {
                    if (path_.empty()) {
                        return branch_node.value();
                    }
                    auto next = branch_node.get_branches()[std::to_integer<uint8_t>(path_.at(0))];
                    if (!next.empty()) {
                        path_.Consume(1);
                        return mpt_.GetNode(next, path_);
                    }
                    return std::nullopt;
                }

              private:
                const MerklePatriciaTrie& mpt_;
                Path& path_;
            };

            class SetHandler {
              public:
                SetHandler(MerklePatriciaTrie& mpt, Path& path, const std::vector<std::byte>& value)
                    : mpt_(mpt), path_(path), value_(value) {}

                Reference operator()(const LeafNode& leaf) {
                    if (leaf.path == path_) {
                        return mpt_.PutToStorage(LeafNode{path_, value_});
                    }

                    auto commonPrefix = path_.CommonPrefix(leaf.path);

                    path_.Consume(commonPrefix.size());
                    auto leafPath = leaf.path;
                    leafPath.Consume(commonPrefix.size());

                    auto branchReference = CreateBranchNode(path_, value_, leafPath, leaf.value());

                    if (commonPrefix.size() != 0) {
                        return mpt_.PutToStorage(ExtensionNode{commonPrefix, branchReference});
                    }

                    return branchReference;
                }

                Reference operator()(const ExtensionNode& extension_node) {
                    if (path_.StartsWith(extension_node.path)) {
                        path_.Consume(extension_node.path.size());
                        auto newReference =
                            mpt_.SetNode(extension_node.get_next_ref(), path_, value_);
                        return mpt_.PutToStorage(ExtensionNode{extension_node.path, newReference});
                    }

                    auto commonPrefix = path_.CommonPrefix(extension_node.path);

                    path_.Consume(commonPrefix.size());
                    auto extensionPath = extension_node.path;
                    extensionPath.Consume(commonPrefix.size());

                    std::array<Reference, kBranchesNum> branches{};
                    std::vector<std::byte> branchValue;
                    if (path_.size() == 0) {
                        branchValue = value_;
                    }

                    CreateBranchLeaf(path_, value_, branches);
                    CreateBranchExtension(extensionPath, extension_node.get_next_ref(), branches);

                    auto branchReference = mpt_.PutToStorage(BranchNode{branches, branchValue});

                    if (commonPrefix.size() != 0) {
                        return mpt_.PutToStorage(ExtensionNode{commonPrefix, branchReference});
                    }
                    return branchReference;
                }

                Reference operator()(const BranchNode& branch_node) {
                    if (path_.size() == 0) {
                        return mpt_.PutToStorage(BranchNode{branch_node.get_branches(), value_});
                    }

                    auto nibble = path_.at(0);
                    path_.Consume(1);
                    auto newReference =
                        mpt_.SetNode(branch_node.get_branches()[std::to_integer<uint8_t>(nibble)],
                                     path_, value_);

                    auto newBranches = branch_node.get_branches();
                    newBranches[std::to_integer<uint8_t>(nibble)] = newReference;

                    return mpt_.PutToStorage(BranchNode{newBranches, branch_node.value()});
                }

              private:
                // If path isn't empty, creates leaf node and stores reference in appropriate
                // branch.
                void CreateBranchLeaf(Path path, const std::vector<std::byte>& val,
                                      std::array<Reference, kBranchesNum>& branches) {
                    if (path.size() > 0) {
                        const auto nibble = path.at(0);
                        path.Consume(1);
                        auto leaf = mpt_.PutToStorage(LeafNode(path, val));
                        branches[std::to_integer<uint8_t>(nibble)] = leaf;
                    }
                }

                Reference CreateBranchNode(const Path& lhsPath,
                                           const std::vector<std::byte>& lhs_val,
                                           const Path& rhsPath,
                                           const std::vector<std::byte>& rhs_val) {
                    if (lhsPath.size() == 0 && rhsPath.size() == 0) {
                        throw std::runtime_error("invalid action");
                    }

                    std::array<Reference, kBranchesNum> branches;

                    std::vector<std::byte> val;
                    if (lhsPath.size() == 0) {
                        val = lhs_val;
                    } else if (rhsPath.size() == 0) {
                        val = rhs_val;
                    }
                    CreateBranchLeaf(lhsPath, lhs_val, branches);
                    CreateBranchLeaf(rhsPath, rhs_val, branches);

                    return mpt_.PutToStorage(BranchNode(branches, val));
                }

                void CreateBranchExtension(Path path, const Reference& nextRef,
                                           std::array<Reference, kBranchesNum>& branches) {
                    if (path.size() == 0) {
                        throw std::runtime_error(
                            "Path for extension node should contain at least one nibble");
                    }

                    if (path.size() == 1) {
                        branches[std::to_integer<uint8_t>(path.at(0))] = nextRef;
                    } else {
                        std::byte nibble = path.at(0);

                        path.Consume(1);

                        auto reference = mpt_.PutToStorage(ExtensionNode(path, nextRef));
                        branches[std::to_integer<uint8_t>(nibble)] = reference;
                    }
                }

                MerklePatriciaTrie& mpt_;
                Path& path_;
                const std::vector<std::byte>& value_;
            };

            enum class DeleteAction { Unknown, Deleted, Updated, UselessBranch };

            struct DeletionInfo {
                Path path;
                std::optional<Reference> ref;
            };

            struct DeleteResult {
                DeleteAction action;
                std::optional<DeletionInfo> info;
            };

            class DeleteHandler {
              public:
                DeleteHandler(MerklePatriciaTrie& mpt, const Path& path) : mpt_(mpt), path_(path) {}

                DeleteResult operator()(const LeafNode& leaf) {
                    if (path_ == leaf.path) {
                        return {DeleteAction::Deleted, std::nullopt};
                    }
                    throw std::runtime_error("Key not found");
                }

                DeleteResult operator()(const ExtensionNode& extension_node) {
                    if (!path_.StartsWith(extension_node.path)) {
                        throw std::runtime_error("Key not found");
                    }

                    Path remaining_path = path_;
                    remaining_path.Consume(extension_node.path.size());
                    auto result = mpt_.DeleteNode(extension_node.get_next_ref(), remaining_path);

                    switch (result.action) {
                        case DeleteAction::Deleted:
                            return {DeleteAction::Deleted, std::nullopt};

                        case DeleteAction::Updated:
                            if (!result.info || !result.info->ref) {
                                throw std::runtime_error("Invalid update info");
                            }
                            return {
                                DeleteAction::Updated,
                                DeletionInfo{{},
                                             mpt_.PutToStorage(ExtensionNode{
                                                 extension_node.path, result.info->ref.value()})}};

                        case DeleteAction::UselessBranch:
                            if (!result.info || !result.info->ref) {
                                throw std::runtime_error("Invalid useless branch info");
                            }
                            return handleUselessBranch(extension_node, result.info.value());

                        default:
                            throw std::runtime_error("Invalid action");
                    }
                }

                DeleteResult operator()(const BranchNode& branch_node) {
                    DeleteAction action;
                    std::optional<DeletionInfo> info;
                    std::byte idx;
                    auto branch_copy = branch_node;

                    if (path_.empty() && branch_node.value().empty()) {
                        throw std::runtime_error("Key not found");
                    } else if (path_.empty() && !branch_node.value().empty()) {
                        branch_copy.set_value({});
                        action = DeleteAction::Deleted;
                    } else {
                        idx = path_.at(0);

                        if (branch_node.get_branches()[std::to_integer<uint8_t>(idx)].empty()) {
                            throw std::runtime_error("Key not found");
                        }

                        Path remaining_path = path_;
                        remaining_path.Consume(1);
                        auto result = mpt_.DeleteNode(
                            branch_node.get_branches()[std::to_integer<uint8_t>(idx)],
                            remaining_path);
                        action = result.action;
                        info = result.info;
                    }

                    return HandleBranchDeleteResult(branch_copy, action, info, idx);
                }

              private:
                MerklePatriciaTrie& mpt_;
                const Path& path_;

                DeleteResult handleUselessBranch(const ExtensionNode& extension_node,
                                                 const DeletionInfo& info) {
                    auto child_node = mpt_.GetFromStorage(info.ref.value());

                    return std::visit(
                        overloaded{[&](const LeafNode& leaf_child) -> DeleteResult {
                                       auto new_path = extension_node.path + leaf_child.path;
                                       return {DeleteAction::Updated,
                                               DeletionInfo{{},
                                                            mpt_.PutToStorage(LeafNode{
                                                                new_path, leaf_child.value()})}};
                                   },
                                   [&](const ExtensionNode& extension_child) -> DeleteResult {
                                       auto new_path = extension_node.path + extension_child.path;
                                       return {DeleteAction::Updated,
                                               DeletionInfo{
                                                   {},
                                                   mpt_.PutToStorage(ExtensionNode{
                                                       new_path, extension_child.get_next_ref()})}};
                                   },
                                   [&](const BranchNode&) -> DeleteResult {
                                       auto new_path = extension_node.path + info.path;
                                       return {DeleteAction::Updated,
                                               DeletionInfo{{},
                                                            mpt_.PutToStorage(ExtensionNode{
                                                                new_path, info.ref.value()})}};
                                   }},
                        child_node);
                }

                DeleteResult HandleBranchDeleteResult(const BranchNode& branch_node,
                                                      DeleteAction action,
                                                      const std::optional<DeletionInfo>& info,
                                                      std::byte idx) {
                    switch (action) {
                        case DeleteAction::Deleted:
                            return HandleBranchDeletion(branch_node, idx);

                        case DeleteAction::Updated:
                        case DeleteAction::UselessBranch:
                            if (info && info->ref) {
                                auto updated_branch = branch_node;
                                updated_branch.SetBranch(idx, info->ref.value());
                                return {DeleteAction::Updated,
                                        DeletionInfo{{}, mpt_.PutToStorage(updated_branch)}};
                            }
                            throw std::runtime_error("Invalid update info");

                        default:
                            throw std::runtime_error("Invalid action");
                    }
                }

                DeleteResult HandleBranchDeletion(const BranchNode& branch_node, std::byte idx) {
                    auto branches = branch_node.get_branches();
                    size_t valid_branches =
                        std::count_if(branches.begin(), branches.end(),
                                      [](const Reference& ref) { return !ref.empty(); });

                    if (valid_branches == 0 && branch_node.value().empty()) {
                        return {DeleteAction::Deleted, std::nullopt};
                    } else if (valid_branches == 0 && !branch_node.value().empty()) {
                        Path new_path;  // Empty path
                        return {DeleteAction::UselessBranch,
                                DeletionInfo{new_path, mpt_.PutToStorage(LeafNode{
                                                           new_path, branch_node.value()})}};
                    } else if (valid_branches == 1 && branch_node.value().empty()) {
                        return BuildNewNodeFromLastBranch(branches);
                    } else {
                        auto updated_branch = branch_node;
                        updated_branch.ClearBranch(idx);
                        return {DeleteAction::Updated,
                                DeletionInfo{{}, mpt_.PutToStorage(updated_branch)}};
                    }
                }

                DeleteResult BuildNewNodeFromLastBranch(
                    const std::array<Reference, kBranchesNum>& branches) {
                    // Find the index of the only stored branch.
                    auto it = std::find_if(branches.begin(), branches.end(),
                                           [](const Reference& ref) { return !ref.empty(); });
                    if (it == branches.end()) {
                        throw std::runtime_error("No valid branches found");
                    }

                    uint8_t idx = std::distance(branches.begin(), it);

                    // Path in leaf will contain one nibble (at this step).
                    Path prefixNibble({std::byte{idx}}, 1);
                    auto child = mpt_.GetFromStorage(*it);

                    return std::visit(
                        overloaded{
                            [&](const LeafNode& leaf_child) -> DeleteResult {
                                auto path = prefixNibble + leaf_child.path;
                                return {DeleteAction::UselessBranch,
                                        DeletionInfo{path, mpt_.PutToStorage(LeafNode{
                                                               path, leaf_child.value()})}};
                            },
                            [&](const ExtensionNode& extension_child) -> DeleteResult {
                                auto path = prefixNibble + extension_child.path;
                                return {
                                    DeleteAction::UselessBranch,
                                    DeletionInfo{path, mpt_.PutToStorage(ExtensionNode{
                                                           path, extension_child.get_next_ref()})}};
                            },
                            [&](const BranchNode&) -> DeleteResult {
                                return {DeleteAction::UselessBranch,
                                        DeletionInfo{prefixNibble, mpt_.PutToStorage(ExtensionNode{
                                                                       prefixNibble, *it})}};
                            }},
                        child);
                }
            };
        }  // namespace details

        // Crypto3 compiles so slow... Use this dummy hash for testing.
        //   Hash we are going to use is still willing to change anyway
        std::array<std::byte, 64> BasicHash(const std::vector<std::byte>& key) {
            std::array<std::byte, 64> result = {std::byte{0}};

            for (size_t i = 0; i < key.size(); ++i) {
                result[i % 64] ^= key[i];
            }

            for (size_t i = 0; i < 64; ++i) {
                result[i] ^= result[(i + 1) % 64];
                result[i] = (result[i] << 1) | (result[i] >> 7);
            }

            return result;
        }

        MerklePatriciaTrie::MerklePatriciaTrie(){};

        Path MerklePatriciaTrie::PathFromKey(const std::vector<std::byte>& key) {
            std::vector<std::byte> hash_result;
            if (key.size() > kMaxRawKeyLen) {
                auto hash_array = BasicHash(key);
                hash_result = std::vector<std::byte>(hash_array.begin(), hash_array.end());
            } else {
                hash_result = key;
            }

            return Path(hash_result);
        }

        std::vector<std::byte> MerklePatriciaTrie::get(const std::vector<std::byte>& key) const {
            if (root_.empty()) {
                throw std::runtime_error("Not initialized MPT");
            }

            auto path = PathFromKey(key);
            auto result = GetNode(root_, path);

            if (result) {
                return *result;
            }
            throw std::runtime_error("Key not found");
        }

        std::optional<std::vector<std::byte>> MerklePatriciaTrie::GetNode(const Reference& node_ref,
                                                                          Path& path) const {
            auto node = GetFromStorage(node_ref);
            return std::visit(details::GetHandler(*this, path), node);
        }

        void MerklePatriciaTrie::set(const std::vector<std::byte>& key,
                                     const std::vector<std::byte>& value) {
            auto path = PathFromKey(key);
            root_ = SetNode(root_, path, value);
        }

        void MerklePatriciaTrie::remove(const std::vector<std::byte>& key) {
            if (root_.empty()) {
                return;
            }

            auto path = PathFromKey(key);
            auto result = DeleteNode(root_, path);

            switch (result.action) {
                case details::DeleteAction::Deleted: {
                    root_.clear();
                }
                case details::DeleteAction::Updated: {
                }
                case details::DeleteAction::Unknown: {
                    root_ = *(result.info->ref);
                    return;
                }
                default: {
                    throw std::runtime_error("remove error");
                }
            }
        }

        details::DeleteResult MerklePatriciaTrie::DeleteNode(const Reference& node_ref,
                                                             const Path& path) {
            auto node = GetFromStorage(node_ref);
            return std::visit(details::DeleteHandler(*this, path), node);
        }

        Node MerklePatriciaTrie::GetFromStorage(const Reference& ref) const {
            if (ref.size() < 32) {
                return DecodeNode(ref);
            }
            auto it = nodes_.find(ref);
            if (it == nodes_.end()) {
                throw std::runtime_error("Node not found");
            }

            return DecodeNode(it->second);
        }

        Reference MerklePatriciaTrie::PutToStorage(const Node& node) {
            Bytes encoded = std::visit([](const auto& n) { return n.Encode(); }, node);
            if (encoded.size() < 32) {
                return encoded;
            }
            auto key_arr = BasicHash(encoded);
            Bytes key(key_arr.begin(), key_arr.end());
            nodes_[key] = encoded;
            return key;
        }

        Reference MerklePatriciaTrie::SetNode(const Reference& node_ref, Path& path,
                                              const std::vector<std::byte>& value) {
            if (node_ref.empty()) {
                return PutToStorage(LeafNode{path, value});
            }

            auto node = GetFromStorage(node_ref);
            return std::visit(details::SetHandler(*this, path, value), node);
        }

    }  // namespace mpt
}  // namespace core
