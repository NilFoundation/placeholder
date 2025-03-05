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

contract MemoryGasTest {
    /**
     * @dev Internal helper to expand memory by `size` bytes.
     *      Forces memory allocation by storing a word at the end.
     */
    function _expandMemory(uint256 size) internal pure {
        assembly {
            // Current free memory pointer (https://docs.soliditylang.org/en/latest/internals/layout_in_memory.html)
            let ptr := mload(0x40)

            // Move it `size` bytes forward
            let newPtr := add(ptr, size)

            // Store something at newPtr to force allocation
            mstore(newPtr, 0)

            // Update the free memory pointer
            mstore(0x40, add(newPtr, 0x20))
        }
    }

    /**
     * @notice Expands memory, then copies call data into a new bytes array.
     */
    function testCalldatacopy(
        uint256 memSize,
        uint256 start,
        uint256 len
    ) external pure returns (bytes memory) {
        _expandMemory(memSize);

        bytes memory result = new bytes(len);
        assembly {
            let dest := add(result, 0x20)
            calldatacopy(dest, start, len)
        }
        return result;
    }

    /**
     * @notice Expands memory, then copies code from this contract’s bytecode.
     */
    function testCodecopy(
        uint256 memSize,
        uint256 codeOffset,
        uint256 len
    ) external pure returns (bytes memory) {
        _expandMemory(memSize);

        bytes memory result = new bytes(len);
        assembly {
            let dest := add(result, 0x20)
            codecopy(dest, codeOffset, len)
        }
        return result;
    }

    /**
     * @notice Expands memory, then demonstrates a naive memory-to-memory copy in assembly.
     */
    function testMemCopy(
        uint256 memSize,
        uint256 src,
        uint256 len
    ) external pure returns (bytes memory) {
        _expandMemory(memSize);

        // We'll create a new buffer for demonstration
        bytes memory result = new bytes(len);
        assembly {
            mcopy(result, src, len)
        }
        return result;
    }


    function _returnSomeData() external pure returns (bytes memory) {
        return "Hello, I am your return data!";
    }

    function testReturndatacopy(
        uint256 memSize,
        uint256 offset,
        uint256 len
    ) external returns (bytes memory) {
        _expandMemory(memSize);

        // Call this contract’s own _returnSomeData()
        // by encoding its selector and arguments
        (bool success, ) = address(this).call(
            abi.encodeWithSelector(this._returnSomeData.selector)
        );

        require(success, "Sub-call failed.");

        // Copy from the return data buffer into new memory
        bytes memory ret = new bytes(len);
        assembly {
            let dest := add(ret, 0x20)
            returndatacopy(dest, offset, len)
        }

        // 3) Return the copied slice
        return ret;
    }

    function testMload(
        uint256 memSize,
        uint256 slot
    ) external pure returns (uint256 val) {
        _expandMemory(memSize);

        assembly {
            val := mload(slot)
        }
    }

    /**
     * @notice Expands memory, then demonstrates mstore by writing and reading at `slot`.
     */
    function testMstore(
        uint256 memSize,
        uint256 slot,
        uint256 value
    ) external pure returns (uint256) {
        _expandMemory(memSize);

        uint256 val;
        assembly {
            mstore(slot, value)
            val := mload(slot)
        }
        return val;
    }

    /**
     * @notice Expands memory, then demonstrates mstore8 by writing a single byte at `slot`.
     */
    function testMstore8(
        uint256 memSize,
        uint256 slot,
        uint8 value
    ) external pure returns (uint8 storedByte) {
        _expandMemory(memSize);

        assembly {
            mstore8(slot, value)
            // mload returns 32 bytes; isolate the lowest-order byte
            storedByte := byte(0, mload(slot))
        }
    }
}
