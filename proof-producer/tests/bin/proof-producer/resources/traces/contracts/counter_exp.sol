// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleStorage {
    uint256 private value;

    event ValueChanged(uint256 newValue);

    function exp() public {
        value += 3;
        value = value**5;
        emit ValueChanged(value);
    }
}
