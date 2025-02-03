// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleStorage {
    uint256 private value;

    event ValueChanged(uint256 newValue);

    function increment() public {
        value += 1;
        emit ValueChanged(value);
    }

    function exponentiate() public {
        if (value < 2) {
            value = 2;
        }
        value = value ** value;
        emit ValueChanged(value);
    }
}
