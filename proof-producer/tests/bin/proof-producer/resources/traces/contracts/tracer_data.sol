// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleStorage {
    uint256 private value;
    bytes32 private hash;

    event ValueChanged(uint256 newValue);

    function increment() public {
        value += 1;
        hash = keccak256(abi.encodePacked(value));
        emit ValueChanged(value);
    }

    function exponentiate() public {
        if (value < 2) {
            value = 2;
        }
        if (value > 3) {
            value = 3;
        }
        value = value ** value;
        hash = keccak256(abi.encodePacked(value));
        emit ValueChanged(value);
    }
}
