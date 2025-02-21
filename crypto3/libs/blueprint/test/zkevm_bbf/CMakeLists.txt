set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")

# ../ is a bit of a hack, but since we are going to use the list only from subdirectories, it should be fine
set(ZKEVM_BBF_TESTS_FILES
    "../hardhat"
    "../rw"
    "../bytecode"
    "../copy"
    "../exp"
    "../opcodes/pushx"
    "../opcodes/iszero"
    "../opcodes/mod_ops"
    "../opcodes/bitwise"
    "../opcodes/cmp"
    "../opcodes/add_sub"
    "../opcodes/byte_ops"
    "../opcodes/mul"
    "../opcodes/div"
    "../opcodes/jumps"
    "../opcodes/not"
    "../opcodes/exp"
    "../opcodes/calldata"
    "../opcodes/logx"
    "../opcodes/gas"
    "../opcodes/pc"
    "../opcodes/msize"
)

add_subdirectory(single_thread_tests)
add_subdirectory(multi_thread_tests)
