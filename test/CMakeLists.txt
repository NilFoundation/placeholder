include(CMTest)

cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_core)

if(NOT Boost_UNIT_TEST_FRAMEWORK_FOUND)
    cm_find_package(Boost REQUIRED COMPONENTS system unit_test_framework)
endif()

cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}

                       ${Boost_LIBRARIES})

macro(define_core_test name)
    cm_test(NAME core_${name}_test SOURCES ${name}.cpp)

    target_include_directories(core_${name}_test PRIVATE
                               "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/test/include>"
                               "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                               ${Boost_INCLUDE_DIRS})

    set_target_properties(core_${name}_test PROPERTIES
                          CXX_STANDARD 17
                          CXX_STANDARD_REQUIRED TRUE)

    get_target_property(target_type Boost::unit_test_framework TYPE)
    if(target_type STREQUAL "SHARED_LIB")
        target_compile_definitions(core_${name}_test PRIVATE BOOST_TEST_DYN_LINK)
    elseif(target_type STREQUAL "STATIC_LIB")

    endif()
endmacro()

list(APPEND TESTS_NAMES
     match
     string_view
     dictionary
     selective_streaming
     request_timeout
     uri
     local_migration
     native_streaming_classes
     aout
     mock_streaming_classes
     blocking_actor
     ipv6_subnet
     mailbox_element
     to_string
     actor_registry
     ipv4_subnet
     sequencer
     or_else
     task_queue
     actor_factory
     handles
     ipv6_address
     drr_queue
     composable_behavior
     metaprogramming
     local_group
     message_lifetime
     unordered_flat_map
     function_view
     fused_streaming
     custom_exception_handler
     dynamic_spawn
     typed_response_promise
     ipv4_address
     message
     error
     expected
     behavior
     drr_cached_queue
     thread_hook
     pipeline_streaming
     broadcast_downstream_manager
     stateful_actor
     actor_pool
     deep_to_string
     tick_emitter
     typed_spawn
     binary_deserializer
     result
     atom
     serial_reply
     detached_actors
     inbound_path
     sender
     actor_lifetime
     actor_clock
     unit
     continuous_streaming
     composition
     sum_type_token
     serialization
     type_erased_tuple
     sum_type
     constructor_attach
     lifo_inbox
     wdrr_dynamic_multiplexed_queue
     wdrr_fixed_multiplexed_queue
     actor_termination
     simple_timeout
     bounds_checker
     request_response
     fifo_inbox
     inspector
     binary_serializer
     optional)

foreach(TEST_NAME ${TESTS_NAMES})
    define_core_test(${TEST_NAME})
endforeach()