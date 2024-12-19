//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021-2022 Aleksei Moskvin <alalmoskvin@gmail.com>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//
// This example demonstrates the construction of merkle tree for a data array
// using keccak hash function and validation of data presence in the tree

#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/container/merkle/tree.hpp>
#include <nil/crypto3/container/merkle/proof.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::containers;

int main() {

    /* Input data array - 9 elements */
    std::vector<std::array<char, 1> > data_on_leafs = {{'0'}, {'1'}, {'2'}, {'3'}, {'4'}, {'5'}, {'6'}, {'7'}, {'8'}};
    /* Element that is not present in input data */
    std::array<char, 1> element_not_in_tree = {'9'};

    /* Tree construction, each node has three descendants */
    merkle_tree<hashes::keccak_1600<256>, 3> tree =
        make_merkle_tree<hashes::keccak_1600<256>, 3>(data_on_leafs.begin(), data_on_leafs.end());

    /* Proofs for presence of 0th and 3rd elements in the tree */
    merkle_proof<hashes::keccak_1600<256>, 3> proof_leaf_0(tree, 0);
    merkle_proof<hashes::keccak_1600<256>, 3> proof_leaf_3(tree, 3);

    /* Check presence of these elements on positions 0 and 3 */
    std::vector<std::array<char, 1>> data_to_check = {
        data_on_leafs[0],
        data_on_leafs[2],
        element_not_in_tree
    };

    for (size_t i = 0; i < data_to_check.size(); ++i) {
        std::cout << "Check whether leaf " << data_to_check[i][0] << " was in tree in position 0: ";
        std::cout << std::boolalpha << proof_leaf_0.validate(data_to_check[i]) << std::endl;
        std::cout << "Check whether leaf " << data_to_check[i][0] << " was in tree in position 3: ";
        std::cout << std::boolalpha << proof_leaf_3.validate(data_to_check[i]) << std::endl;
    }

    return 0;
}
