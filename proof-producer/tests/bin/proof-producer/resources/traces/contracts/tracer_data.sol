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

contract Uint256CornerCaseTests {
    /// @notice Adds two uint256 numbers using EVM ADD opcode.
    ///         Overflow results in 256-bit wrap-around, no revert.
    function addAsm(uint256 a, uint256 b) external pure returns (uint256 result) {
        assembly {
            result := add(a, b)
        }
    }

    /// @notice Multiplies two uint256 numbers using EVM MUL opcode.
    ///         Overflow results in 256-bit wrap-around, no revert.
    function mulAsm(uint256 a, uint256 b) external pure returns (uint256 result) {
        assembly {
            result := mul(a, b)
        }
    }

    /// @notice Divides a by b using EVM DIV opcode.
    ///         If b == 0, EVM returns 0 (no revert).
    function divAsm(uint256 a, uint256 b) external pure returns (uint256 result) {
        assembly {
            result := div(a, b)
        }
    }

    /// @notice Exponentiates a^b using EVM EXP opcode.
    ///         Large exponents can be very gas-intensive, but won't revert by opcode alone.
    function expAsm(uint256 a, uint256 b) external pure returns (uint256 result) {
        assembly {
            result := exp(a, b)
        }
    }

    /// @notice Subtracts b from a using EVM SUB opcode.
    ///         Underflow results in 256-bit wrap-around, no revert.
    function subAsm(uint256 a, uint256 b) external pure returns (uint256 result) {
        assembly {
            result := sub(a, b)
        }
    }
}
