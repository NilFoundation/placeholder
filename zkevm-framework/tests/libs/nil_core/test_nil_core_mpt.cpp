#include <cstddef>
#include <cstdint>
#include <vector>

#include "gtest/gtest.h"
#include "ssz++.hpp"
#include "zkevm_framework/core/mpt/mpt.hpp"

using namespace core;
using namespace core::mpt;

std::vector<std::byte> stringToByteVector(const std::string& str) {
    std::vector<std::byte> result;
    result.reserve(str.size());
    for (char c : str) {
        result.push_back(static_cast<std::byte>(c));
    }
    return result;
}

TEST(NilCoreMerklePatriciaTrieTest, PathSerialization) {
    std::string current;
    for (std::size_t i = 0; i < 100; ++i) {
        auto pathBytes = stringToByteVector(current);
        Path path{pathBytes};

        const auto serialized = ssz::serialize(path);
        const auto deserialized = ssz::deserialize<Path>(serialized);

        ASSERT_EQ(path, deserialized);

        current += 'a' + (i % 26);
    }
}

TEST(NilCoreMerklePatriciaTrieTest, NodeEncodeDecode) {
    // TODO: add hardcoded input for deserialization to check binary compatability with cluster
    std::string current;
    for (std::size_t i = 0; i < 10; ++i) {
        auto currentBytes = stringToByteVector(current);
        // LeafNode
        Path path{currentBytes};
        std::vector<std::byte> value = currentBytes;
        LeafNode leafNode{path, value};

        auto serialized = leafNode.Encode();
        Node node = DecodeNode(serialized);
        ASSERT_TRUE(std::holds_alternative<LeafNode>(node));
        const auto& leaf = std::get<LeafNode>(node);

        ASSERT_EQ(leaf.value(), value);
        ASSERT_EQ(leaf.path, path);

        // ExtensionNode
        ExtensionNode extensionNode{path, value};

        serialized = extensionNode.Encode();
        node = DecodeNode(serialized);
        ASSERT_TRUE(std::holds_alternative<ExtensionNode>(node));
        const auto& extension = std::get<ExtensionNode>(node);

        ASSERT_EQ(extension.path, path);
        ASSERT_EQ(extension.get_next_ref(), value);

        // BranchNode
        std::array<Reference, kBranchesNum> branches;
        for (std::size_t i = 0; i < kBranchesNum; ++i) {
            branches[i] = value;
        }
        BranchNode branchNode(branches, value);

        serialized = branchNode.Encode();
        node = DecodeNode(serialized);
        ASSERT_TRUE(std::holds_alternative<BranchNode>(node));
        const auto& branch = std::get<BranchNode>(node);

        ASSERT_EQ(branch.value(), value);
        ASSERT_EQ(branch.get_branches(), branches);
        current += 'a' + (i % 26);
    }
}

TEST(NilCoreMerklePatriciaTrieTest, InsertGetMany) {
    MerklePatriciaTrie trie;

    std::vector<std::pair<std::string, std::string>> cases = {
        {"do", "verb"}, {"dog", "puppy"}, {"doge", "coin"}, {"horse", "stallion"}};

    for (const auto& [key, value] : cases) {
        ASSERT_NO_THROW(trie.set(stringToByteVector(key), stringToByteVector(value)));
    }

    for (const auto& [key, expectedValue] : cases) {
        std::vector<std::byte> result;
        result = trie.get(stringToByteVector(key));
        ASSERT_NO_THROW(result = trie.get(stringToByteVector(key)));
        ASSERT_EQ(result, stringToByteVector(expectedValue));
    }
}

TEST(NilCoreMerklePatriciaTrieTest, TestDelete) {
    Path p;
    MerklePatriciaTrie trie;

    std::vector<std::pair<std::string, std::string>> cases = {
        {"do", "verb"}, {"dog", "puppy"}, {"doge", "coin"}, {"horse", "stallion"}};

    for (const auto& [key, value] : cases) {
        ASSERT_NO_THROW(trie.set(stringToByteVector(key), stringToByteVector(value)));
    }

    ASSERT_NO_THROW(trie.remove(stringToByteVector("do")));
    ASSERT_ANY_THROW(trie.remove(stringToByteVector("do")));  // Can't remove twice
    ASSERT_ANY_THROW(trie.remove(stringToByteVector("d")));   // Can't remove absent
    ASSERT_NO_THROW(trie.remove(stringToByteVector("doge")));

    ASSERT_ANY_THROW(trie.get(stringToByteVector("do")));    // Can't access removed
    ASSERT_ANY_THROW(trie.get(stringToByteVector("doge")));  // Can't access removed

    ASSERT_NO_THROW(trie.get(stringToByteVector("dog")));    // Can access existing
    ASSERT_NO_THROW(trie.get(stringToByteVector("horse")));  // Can access existing
}
