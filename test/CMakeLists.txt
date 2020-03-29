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
     expected
     selective_streaming
     unordered_flat_map
     type_id_list
     drr_cached_queue
     or_else
     handles
     span
     actor_pool
     bounds_checker
     sequencer
     string_view
     categorized
     tracing_data
     composable_behavior
     ipv6_subnet
     ipv4_address
     make_config_value_field
     sum_type
     ripemd_160
     message_id
     ipv6_address
     read_ini
     metaprogramming
     config_option_set
     actor_profiler
     aout
     optional
     type_id_list_builder
     variant
     mailbox_element
     serialization
     config_value
     ringbuffer
     read_bool
     logger
     continuous_streaming
     read_string
     detached_actors
     message
     native_streaming_classes
     function_view
     request_timeout
     ipv4_subnet
     result
     config_option
     constructor_attach
     wdrr_dynamic_multiplexed_queue
     actor_clock
     read_number
     unique_function
     requester
     binary_deserializer
     select_any
     serial_reply
     actor_registry
     fifo_inbox
     custom_exception_handler
     inspector
     read_floating_point
     cow_tuple
     config_value_adaptor
     lifo_inbox
     deep_to_string
     message_builder_element
     error
     meta_object
     fused_downstream_manager
     parse
     settings
     blocking_actor
     simple_timeout
     mock_streaming_classes
     serialized_size
     sender
     thread_hook
     typed_behavior
     read_number_or_timespan
     binary_serializer
     wdrr_fixed_multiplexed_queue
     typed_message_view
     task_queue
     intrusive_ptr
     pipeline_streaming
     typed_response_promise
     node_id
     typed_spawn
     const_typed_message_view
     read_unsigned_integer
     actor_lifetime
     unit
     byte
     string_algorithms
     read_signed_integer
     stateful_actor
     behavior
     broadcast_downstream_manager
     composition
     ini_consumer
     limited_vector
     uri
     select_all
     dynamic_spawn
     tick_emitter
     drr_queue
     ipv6_endpoint
     local_group
     dictionary
     message_lifetime
     actor_factory
     read_timespan
     actor_termination
     spawner_config
     ipv4_endpoint)

foreach(TEST_NAME ${TESTS_NAMES})
    define_core_test(${TEST_NAME})
endforeach()