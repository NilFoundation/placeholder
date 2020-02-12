cmake_minimum_required(VERSION 3.12.4)

cmake_policy(SET CMP0028 NEW)
cmake_policy(SET CMP0042 NEW)
cmake_policy(SET CMP0048 NEW)
cmake_policy(SET CMP0057 NEW)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake"
     "${CMAKE_CURRENT_LIST_DIR}/cmake/packages"
     "${CMAKE_CURRENT_LIST_DIR}/cmake/modules/share/modules/cmake")

include(CMConfig)
include(CMDeploy)
include(CMSetupVersion)

if(NOT CMAKE_WORKSPACE_NAME OR NOT ("${CMAKE_WORKSPACE_NAME}" STREQUAL "mtl"))
    cm_workspace(mtl)
endif()

macro(cm_find_package NAME)
    if(NOT "${NAME}" MATCHES "^${CMAKE_WORKSPACE_NAME}_.*$" AND NOT "${NAME}" STREQUAL CM)
        find_package(${ARGV})
    else()
        set(${ARGV0}_FOUND ON CACHE BOOL "")
    endif()
endmacro()

cm_project(actor WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME} LANGUAGES C CXX)

cm_setup_version(VERSION 0.16.0)

if(NOT Boost_FOUND)
    cm_find_package(Boost COMPONENTS chrono program_options random system thread)
endif()

# get header files; only needed by CMake generators,
# e.g., for creating proper Xcode projects
file(GLOB_RECURSE ${CURRENT_PROJECT_NAME}_HEADERS "include/nil/actor/**.hpp")

# list cpp files excluding platform-dependent files
set(${CURRENT_PROJECT_NAME}_SOURCES
    src/abstract_actor.cpp
    src/abstract_channel.cpp
    src/abstract_composable_behavior.cpp
    src/abstract_coordinator.cpp
    src/abstract_group.cpp
    src/abstract_worker.cpp
    src/abstract_worker_hub.cpp
    src/actor.cpp
    src/actor_addr.cpp
    src/actor_clock.cpp
    src/actor_companion.cpp
    src/actor_config.cpp
    src/actor_control_block.cpp
    src/actor_ostream.cpp
    src/actor_pool.cpp
    src/actor_proxy.cpp
    src/actor_registry.cpp
    src/spawner.cpp
    src/spawner_config.cpp
    src/append_percent_encoded.cpp
    src/atom.cpp
    src/attachable.cpp
    src/behavior.cpp
    src/behavior_impl.cpp
    src/behavior_stack.cpp
    src/binary_deserializer.cpp
    src/binary_serializer.cpp
    src/blocking_actor.cpp
    src/blocking_behavior.cpp
    src/chars.cpp
    #    src/concatenated_tuple.cpp
    src/config_value.cpp
    #    src/decorated_tuple.cpp
    src/default_attachable.cpp
    src/defaults.cpp
    src/deserializer.cpp
    src/downstream_manager.cpp
    src/downstream_manager_base.cpp
    src/downstream_messages.cpp
    src/duration.cpp
    src/dynamic_message_data.cpp
    src/error.cpp
    src/event_based_actor.cpp
    src/execution_unit.cpp
    src/exit_reason.cpp
    src/fnv_hash.cpp
    src/forwarding_actor_proxy.cpp
    src/get_mac_addresses.cpp
    src/get_process_id.cpp
    src/get_root_uuid.cpp
    src/group.cpp
    src/group_manager.cpp
    src/group_module.cpp
    src/inbound_path.cpp
    src/invoke_result_visitor.cpp
    src/ipv4_address.cpp
    src/ipv4_endpoint.cpp
    src/ipv4_subnet.cpp
    src/ipv6_address.cpp
    src/ipv6_endpoint.cpp
    src/ipv6_subnet.cpp
    src/local_actor.cpp
    src/logger.cpp
    src/mailbox_element.cpp
    src/match_case.cpp
    src/memory_managed.cpp
    #    src/merged_tuple.cpp
    src/message.cpp
    src/message_builder.cpp
    src/message_data.cpp
    src/message_handler.cpp
    src/message_view.cpp
    src/monitorable_actor.cpp
    src/node_id.cpp
    src/outbound_path.cpp
    src/parse.cpp
    src/pec.cpp
    src/pretty_type_name.cpp
    src/private_thread.cpp
    src/proxy_registry.cpp
    src/raise_error.cpp
    src/raw_event_based_actor.cpp
    src/ref_counted.cpp
    src/replies_to.cpp
    src/response_promise.cpp
    src/resumable.cpp
    src/rtti_pair.cpp
    src/runtime_settings_map.cpp
    src/scheduled_actor.cpp
    src/scoped_actor.cpp
    src/scoped_execution_unit.cpp
    src/sec.cpp
    src/sequencer.cpp
    src/error_code.cpp
    src/serializer.cpp
    src/set_thread_name.cpp
    src/shared_spinlock.cpp
    src/simple_actor_clock.cpp
    src/skip.cpp
    #    src/splitter.cpp
    src/stream_aborter.cpp
    src/stream_manager.cpp
    src/stream_priority.cpp
    src/string_algorithms.cpp
    src/string_view.cpp
    src/stringification_inspector.cpp
    src/sync_request_bouncer.cpp
    src/term.cpp
    src/test_actor_clock.cpp
    src/test_coordinator.cpp
    src/thread_hook.cpp
    src/thread_safe_actor_clock.cpp
    src/tick_emitter.cpp
    src/timestamp.cpp
    src/try_match.cpp
    src/type_erased_tuple.cpp
    src/type_erased_value.cpp
    src/uniform_type_info_map.cpp
    src/unprofiled.cpp
    src/uri.cpp
    src/uri_builder.cpp
    src/uri_impl.cpp
    src/work_sharing.cpp
    src/work_stealing.cpp
    )

# configure build_config.hpp header
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/cmake/build_config.hpp.in"
               "${CMAKE_BINARY_DIR}/include/nil/mtl/detail/build_config.hpp"
               @ONLY)
install(FILES "${CMAKE_BINARY_DIR}/include/nil/mtl/detail/build_config.hpp"
        DESTINATION include/nil/mtl/detail)
list(APPEND LIBMTL_CORE_HDRS
     "${CMAKE_BINARY_DIR}/include/nil/mtl/detail/build_config.hpp")

add_library(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} ${${CURRENT_PROJECT_NAME}_SOURCES}
            ${${CURRENT_PROJECT_NAME}_HEADERS} ${LIBMTL_CORE_HDRS})
set_target_properties(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTIES
                      LINKER_LANGUAGE CXX
                      EXPORT_NAME ${CURRENT_PROJECT_NAME}
                      CXX_STANDARD 17
                      CXX_STANDARD_REQUIRED TRUE)

target_include_directories(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PUBLIC
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                           $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>

                           ${Boost_INCLUDE_DIRS})

target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PUBLIC
                      ${MTL_EXTRA_LDFLAGS}

                      crypto3::block
                      crypto3::codec
                      crypto3::hash

                      marshalling

                      ${Boost_LIBRARIES})

cm_deploy(TARGETS ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
          INCLUDE include
          NAMESPACE ${CMAKE_WORKSPACE_NAME}::)

if(APPLE OR NOT ${CMAKE_TARGET_ARCHITECTURE} STREQUAL ${CMAKE_HOST_SYSTEM_PROCESSOR})
    set_target_properties(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTIES
                          XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY "${APPLE_CODE_SIGN_IDENTITY}"
                          XCODE_ATTRIBUTE_DEVELOPMENT_TEAM "${CMAKE_XCODE_ATTRIBUTE_DEVELOPMENT_TEAM}")
endif()

if(BUILD_TESTS)
    add_subdirectory(test)
endif()