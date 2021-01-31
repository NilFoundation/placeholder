cmake_minimum_required(VERSION 3.12.4)

cmake_policy(SET CMP0028 NEW)
cmake_policy(SET CMP0042 NEW)
cmake_policy(SET CMP0048 NEW)
cmake_policy(SET CMP0057 NEW)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake"
    "${CMAKE_CURRENT_LIST_DIR}/cmake/packages"
    "${CMAKE_CURRENT_LIST_DIR}/cmake/modules/share/modules/cmake")

cm_find_package(CM)

include(CMConfig)
include(CMDeploy)
include(CMSetupVersion)

if(NOT CMAKE_WORKSPACE_NAME OR NOT ("${CMAKE_WORKSPACE_NAME}" STREQUAL "actor"))
    cm_workspace(actor)
endif()

macro(cm_find_package NAME)
    if(NOT "${NAME}" MATCHES "^${CMAKE_WORKSPACE_NAME}_.*$" AND NOT "${NAME}" STREQUAL CM)
        find_package(${ARGV})
    else()
        set(${ARGV0}_FOUND ON CACHE BOOL "")
    endif()
endmacro()

cm_project(core WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME} LANGUAGES CXX)

cm_setup_version(VERSION 0.1.0)

if(BUILD_WITH_DPDK)
    set(seastar_dpdk_obj seastar-dpdk.o)
endif()

set(${CURRENT_PROJECT_NAME}_HEADERS
    ${seastar_dpdk_obj}
    include/nil/actor/core/abort_source.hh
    include/nil/actor/core/alien.hh
    include/nil/actor/core/align.hh
    include/nil/actor/core/aligned_buffer.hh
    include/nil/actor/core/app-template.hh
    include/nil/actor/core/apply.hh
    include/nil/actor/core/array_map.hh
    include/nil/actor/core/bitops.hh
    include/nil/actor/core/bitset-iter.hh
    include/nil/actor/core/byteorder.hh
    include/nil/actor/core/cacheline.hh
    include/nil/actor/core/checked_ptr.hh
    include/nil/actor/core/chunked_fifo.hh
    include/nil/actor/core/circular_buffer.hh
    include/nil/actor/core/circular_buffer_fixed_capacity.hh
    include/nil/actor/core/condition-variable.hh
    include/nil/actor/core/deleter.hh
    include/nil/actor/core/distributed.hh
    include/nil/actor/core/do_with.hh
    include/nil/actor/core/dpdk_rte.hh
    include/nil/actor/core/enum.hh
    include/nil/actor/core/exception_hacks.hh
    include/nil/actor/core/execution_stage.hh
    include/nil/actor/core/expiring_fifo.hh
    include/nil/actor/core/fair_queue.hh
    include/nil/actor/core/file.hh
    include/nil/actor/core/file-types.hh
    include/nil/actor/core/fsqual.hh
    include/nil/actor/core/fstream.hh
    include/nil/actor/core/function_traits.hh
    include/nil/actor/core/future-util.hh
    include/nil/actor/core/future.hh
    include/nil/actor/core/gate.hh
    include/nil/actor/core/iostream-impl.hh
    include/nil/actor/core/iostream.hh
    include/nil/actor/detail/later.hh
    include/nil/actor/core/layered_file.hh
    include/nil/actor/core/linux-aio.hh
    include/nil/actor/core/loop.hh
    include/nil/actor/core/lowres_clock.hh
    include/nil/actor/core/manual_clock.hh
    include/nil/actor/core/map_reduce.hh
    include/nil/actor/core/memory.hh
    include/nil/actor/core/metrics.hh
    include/nil/actor/core/metrics_api.hh
    include/nil/actor/core/metrics_registration.hh
    include/nil/actor/core/metrics_types.hh
    include/nil/actor/core/pipe.hh
    include/nil/actor/core/posix.hh
    include/nil/actor/core/preempt.hh
    include/nil/actor/core/prefetch.hh
    include/nil/actor/core/print.hh
    include/nil/actor/core/prometheus.hh
    include/nil/actor/core/queue.hh
    include/nil/actor/core/ragel.hh
    include/nil/actor/core/reactor.hh
    include/nil/actor/core/report_exception.hh
    include/nil/actor/core/resource.hh
    include/nil/actor/core/rwlock.hh
    include/nil/actor/core/scattered_message.hh
    include/nil/actor/core/scheduling.hh
    include/nil/actor/core/scollectd.hh
    include/nil/actor/core/scollectd_api.hh
    include/nil/actor/core/seastar.hh
    include/nil/actor/core/semaphore.hh
    include/nil/actor/core/sharded.hh
    include/nil/actor/core/shared_future.hh
    include/nil/actor/core/shared_mutex.hh
    include/nil/actor/core/shared_ptr.hh
    include/nil/actor/core/shared_ptr_debug_helper.hh
    include/nil/actor/core/shared_ptr_incomplete.hh
    include/nil/actor/core/simple-stream.hh
    include/nil/actor/core/slab.hh
    include/nil/actor/core/sleep.hh
    include/nil/actor/core/sstring.hh
    include/nil/actor/core/stall_sampler.hh
    include/nil/actor/core/stream.hh
    include/nil/actor/core/systemwide_memory_barrier.hh
    include/nil/actor/core/task.hh
    include/nil/actor/core/temporary_buffer.hh
    include/nil/actor/core/thread.hh
    include/nil/actor/core/thread_cputime_clock.hh
    include/nil/actor/core/thread_impl.hh
    include/nil/actor/core/timed_out_error.hh
    include/nil/actor/core/timer-set.hh
    include/nil/actor/core/timer.hh
    include/nil/actor/core/transfer.hh
    include/nil/actor/core/unaligned.hh
    include/nil/actor/core/units.hh
    include/nil/actor/core/vector-data-sink.hh
    include/nil/actor/core/weak_ptr.hh
    include/nil/actor/core/when_all.hh
    include/nil/actor/core/with_scheduling_group.hh
    include/nil/actor/core/with_timeout.hh
    include/nil/actor/detail/alloc_failure_injector.hh
    include/nil/actor/detail/backtrace.hh
    include/nil/actor/detail/concepts.hh
    include/nil/actor/detail/bool_class.hh
    include/nil/actor/detail/conversions.hh
    include/nil/actor/detail/defer.hh
    include/nil/actor/detail/eclipse.hh
    include/nil/actor/detail/function_input_iterator.hh
    include/nil/actor/detail/gcc6-concepts.hh
    include/nil/actor/detail/indirect.hh
    include/nil/actor/detail/is_smart_ptr.hh
    include/nil/actor/detail/lazy.hh
    include/nil/actor/detail/log-cli.hh
    include/nil/actor/detail/log-impl.hh
    include/nil/actor/detail/log.hh
    include/nil/actor/detail/noncopyable_function.hh
    include/nil/actor/detail/optimized_optional.hh
    include/nil/actor/detail/print_safe.hh
    include/nil/actor/detail/program-options.hh
    include/nil/actor/detail/read_first_line.hh
    include/nil/actor/detail/reference_wrapper.hh
    include/nil/actor/detail/spinlock.hh
    include/nil/actor/detail/std-compat.hh
    include/nil/actor/detail/transform_iterator.hh
    include/nil/actor/detail/tuple_utils.hh
    include/nil/actor/detail/variant_utils.hh)

set(${CURRENT_PROJECT_NAME}_SOURCES
    src/core/alien.cc
    src/core/file.cc
    src/core/fair_queue.cc
    src/core/reactor_backend.cc
    src/core/thread_pool.cc
    src/core/app-template.cc
    src/core/dpdk_rte.cc
    src/core/exception_hacks.cc
    src/core/execution_stage.cc
    src/core/file-impl.hh
    src/core/fsnotify.cc
    src/core/fsqual.cc
    src/core/fstream.cc
    src/core/future.cc
    src/core/future-util.cc
    src/core/linux-aio.cc
    src/core/memory.cc
    src/core/metrics.cc
    src/core/on_internal_error.cc
    src/core/posix.cc
    src/core/prometheus.cc
    src/core/reactor.cc
    src/core/resource.cc
    src/core/sharded.cc
    src/core/scollectd.cc
    src/core/scollectd-impl.hh
    src/core/systemwide_memory_barrier.cc
    src/core/smp.cc
    src/core/sstring.cc
    src/core/thread.cc
    src/core/uname.cc
    src/core/vla.hh
    src/core/io_queue.cc
    src/core/semaphore.cc
    src/core/condition-variable.cc
    src/detail/alloc_failure_injector.cc
    src/detail/backtrace.cc
    src/detail/conversions.cc
    src/detail/exceptions.cc
    src/detail/file.cc
    src/detail/log.cc
    src/detail/program-options.cc
    src/detail/read_first_line.cc
    src/detail/tmp_file.cc)

set(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}_PRIVATE_CXX_FLAGS
    -fvisibility=hidden
    -UNDEBUG
    -Wall
    -Werror
    -Wno-array-bounds # Disabled because of https://gcc.gnu.org/bugzilla/show_bug.cgi?id=93437
    -Wno-error=deprecated-declarations)

add_library(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
    ${${CURRENT_PROJECT_NAME}_HEADERS}
    ${${CURRENT_PROJECT_NAME}_SOURCES})

set_target_properties(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTIES
    LINKER_LANGUAGE CXX
    EXPORT_NAME ${CURRENT_PROJECT_NAME}
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED TRUE)

target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PUBLIC
    Boost::boost
    Boost::program_options
    Boost::thread
    c-ares::c-ares
    cryptopp::cryptopp
    fmt::fmt
    lz4::lz4

    PRIVATE
    ${CMAKE_DL_LIBS}
    GnuTLS::gnutls
    StdAtomic::atomic
    #    lksctp-tools::lksctp-tools
    protobuf::libprotobuf
    #    rt::rt
    yaml-cpp::yaml-cpp
    Threads::Threads)

target_include_directories(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PRIVATE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>

    ${CUDA_INCLUDE_DIRS})

if(BUILD_WITH_COMPRESS_DEBUG)
    # -gz doesn't imply -g, so it is safe to add it regardless of debug
    # info being enabled.
    list(APPEND ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}_PRIVATE_CXX_FLAGS -gz)
endif()

set(Seastar_SANITIZE_MODES "Debug" "Sanitize")
if((BUILD_WITH_SANITIZE STREQUAL "ON") OR
    ((BUILD_WITH_SANITIZE STREQUAL "DEFAULT") AND
    (CMAKE_BUILD_TYPE IN_LIST Seastar_SANITIZE_MODES)))
    if(NOT Sanitizers_FOUND)
        message(FATAL_ERROR "Sanitizers not found!")
    endif()
    set(Seastar_Sanitizers_OPTIONS ${Sanitizers_COMPILER_OPTIONS})
    target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PUBLIC
        Sanitizers::address
        Sanitizers::undefined_behavior)
endif()

# We only need valgrind to find uninitialized memory uses, so disable
# the leak sanitizer.
# To test with valgrind run "ctest -T memcheck"
set(MEMORYCHECK_COMMAND_OPTIONS "--error-exitcode=1 --leak-check=no --trace-children=yes" )
include(CTest)

#
# We want asserts enabled on all modes, but cmake defaults to passing
# -DNDEBUG in some modes. We add -UNDEBUG to our private options to
# reenable it. To force asserts off pass -DNDEBUG in
# Seastar_CXX_FLAGS.
#
# To disable -Werror, pass -Wno-error to Seastar_CXX_FLAGS.
#
# We disable _FORTIFY_SOURCE because it generates false positives with longjmp() (src/core/thread.cc)
#

target_compile_options(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PUBLIC
    $<$<COMPILE_LANGUAGE:CXX>:-std=${BUILD_WITH_CXX_DIALECT}>
    -U_FORTIFY_SOURCE)

target_compile_definitions(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PUBLIC
    SEASTAR_API_LEVEL=${BUILD_WITH_API_LEVEL})

function(seastar_supports_flag flag var)
    set(CMAKE_REQUIRED_FLAGS ${flag})
    check_cxx_source_compiles("int main() { return 0; }" result)
    set(${var} ${result} PARENT_SCOPE)
endfunction ()

seastar_supports_flag("-Wno-maybe-uninitialized -Werror" MaybeUninitialized_FOUND)
if(MaybeUninitialized_FOUND)
    target_compile_options(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PUBLIC
        # With std::experimental::optional it is easy to hit
        # https://gcc.gnu.org/bugzilla/show_bug.cgi?id=88897.  We disable
        # -Wmaybe-uninitialized in here since otherwise we would have to
        # disable it on many types used inside optional<>.
        -Wno-maybe-uninitialized)
endif()

if(BUILD_WITH_SSTRING)
    target_compile_options(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PUBLIC -DSEASTAR_SSTRING)
endif()

if(LinuxMembarrier_FOUND)
    list(APPEND ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}_PRIVATE_COMPILE_DEFINITIONS SEASTAR_HAS_MEMBARRIER)

    target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
        PRIVATE LinuxMembarrier::membarrier)
endif()

set(Seastar_ALLOC_FAILURE_INJECTION_MODES "Dev")
if((BUILD_WITH_ALLOC_FAILURE_INJECTION IN_LIST True_STRING_VALUES) OR
    ((BUILD_WITH_ALLOC_FAILURE_INJECTION STREQUAL "DEFAULT") AND
    (CMAKE_BUILD_TYPE IN_LIST Seastar_ALLOC_FAILURE_INJECTION_MODES)))
    target_compile_definitions(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
        PUBLIC SEASTAR_ENABLE_ALLOC_FAILURE_INJECTION)
endif()

if(BUILD_WITH_TASK_BACKTRACE)
    target_compile_definitions(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
        PUBLIC SEASTAR_TASK_BACKTRACE)
endif()

if(BUILD_WITH_DEBUG_ALLOCATIONS)
    target_compile_definitions(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
        PRIVATE SEASTAR_DEBUG_ALLOCATIONS)
endif()

if(Sanitizers_FIBER_SUPPORT)
    list(APPEND ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}_PRIVATE_COMPILE_DEFINITIONS SEASTAR_HAVE_ASAN_FIBER_SUPPORT)
endif()

if(BUILD_WITH_ALLOC_PAGE_SIZE)
    target_compile_definitions(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
        PUBLIC SEASTAR_OVERRIDE_ALLOCATOR_PAGE_SIZE=${BUILD_WITH_ALLOC_PAGE_SIZE})
endif()

if(BUILD_WITH_CXX_FLAGS)
    list(APPEND
        ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}_PRIVATE_CXX_FLAGS
        ${BUILD_WITH_CXX_FLAGS})
endif()

# When using split dwarf --gdb-index is effectively required since
# otherwise gdb is just too slow. We also want to use split dwarf in
# as many compilation units as possible.  So while these flags don't
# have to be public, we don't expect anyone to want to build seastar
# with them and some client code without.
if(BUILD_WITH_SPLIT_DWARF AND (NOT (CMAKE_BUILD_TYPE STREQUAL "Dev")))
    set(Seastar_SPLIT_DWARF_FLAG "-Wl,--gdb-index")
    target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PUBLIC ${Seastar_SPLIT_DWARF_FLAG})
    target_compile_options(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PUBLIC "-gsplit-dwarf")
endif()

if(BUILD_WITH_HEAP_PROFILING)
    set_property(
        SOURCE "src/core/memory.cc"
        PROPERTY
        COMPILE_DEFINITIONS SEASTAR_HEAPPROF)
endif()

if(BUILD_WITH_DPDK)
    if(NOT dpdk_FOUND)
        message(FATAL_ERROR "dpdk support is enabled but it is not available!")
    endif()

    #
    # The DPDK architecture needs to be transitively applied to consumers of Seastar as well.
    #

    set(Seastar_ARCH_FOR_native "native")
    set(Seastar_ARCH_FOR_nhm "nehalem")
    set(Seastar_ARCH_FOR_wsm "westmere")
    set(Seastar_ARCH_FOR_snb "sandybridge")
    set(Seastar_ARCH_FOR_ivb "ivybridge")
    set(Seastar_ARCH_FOR_armv8a "armv8-a")
    set(Seastar_ARCH ${Seastar_ARCH_FOR_${Seastar_DPDK_MACHINE}})

    if(NOT Seastar_ARCH)
        message(FATAL_ERROR "Unrecognized DPDK machine identifier: ${Seastar_DPDK_MACHINE}")
    endif()

    target_compile_options(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
        PUBLIC -march=${Seastar_ARCH})

    target_compile_definitions(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
        PUBLIC SEASTAR_HAVE_DPDK)

    # No pmd driver code will be pulled in without "--whole-archive". To
    # avoid exposing that to seastar users, combine dpdk into a single
    # .o file.
    add_custom_command(
        OUTPUT seastar-dpdk.o
        COMMAND ld -r -o seastar-dpdk.o --whole-archive ${dpdk_LIBRARIES} --no-whole-archive)

    # This just provides the include path to cmake
    target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PUBLIC dpdk::dpdk)
endif()

if(BUILD_WITH_HWLOC)
    if(NOT hwloc_FOUND)
        message(FATAL_ERROR "`hwloc` support is enabled but it is not available!")
    endif()

    list(APPEND ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}_PRIVATE_COMPILE_DEFINITIONS SEASTAR_HAVE_HWLOC)

    target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
        PRIVATE hwloc::hwloc)
endif()

if(BUILD_WITH_LD_FLAGS)
    # In newer versions of CMake, there is `target_link_options`.
    target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
        PRIVATE ${BUILD_WITH_LD_FLAGS})
endif()

if(BUILD_WITH_NUMA)
    if(NOT numactl_FOUND)
        message(FATAL_ERROR "NUMA support is enabled but `numactl` is not available!")
    endif()

    list(APPEND ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}_PRIVATE_COMPILE_DEFINITIONS SEASTAR_HAVE_NUMA)

    target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
        PRIVATE numactl::numactl)
endif()

if(lz4_HAVE_COMPRESS_DEFAULT)
    list(APPEND ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}_PRIVATE_COMPILE_DEFINITIONS SEASTAR_HAVE_LZ4_COMPRESS_DEFAULT)
endif()

seastar_supports_flag("-Werror=unused-result" ErrorUnused_FOUND)
if(ErrorUnused_FOUND)
    if(BUILD_WITH_UNUSED_RESULT_ERROR)
        target_compile_options(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
            PUBLIC -Werror=unused-result)
    else()
        target_compile_options(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
            PUBLIC -Wno-error=unused-result)
    endif()
endif()

if((CMAKE_BUILD_TYPE STREQUAL "Debug") OR (CMAKE_BUILD_TYPE STREQUAL "Sanitize"))
    target_compile_definitions(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
        PUBLIC
        SEASTAR_DEBUG
        SEASTAR_DEFAULT_ALLOCATOR
        SEASTAR_SHUFFLE_TASK_QUEUE)
endif()

set(BUILD_WITH_DEBUG_SHARED_PTR_MODES "Debug" "Sanitize")
if(BUILD_WITH_DEBUG_SHARED_PTR IN_LIST True_STRING_VALUES OR
        ((BUILD_WITH_DEBUG_SHARED_PTR IN_LIST Default_STRING_VALUES) AND
        (CMAKE_BUILD_TYPE IN_LIST BUILD_WITH_DEBUG_SHARED_PTR_MODES)))
        target_compile_definitions(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
            PUBLIC
            SEASTAR_DEBUG_SHARED_PTR)
    endif()

    set(Seastar_STACK_GUARD_MODES "Debug" "Sanitize" "Dev")
    if((BUILD_WITH_STACK_GUARDS STREQUAL "ON") OR
        ((BUILD_WITH_STACK_GUARDS STREQUAL "DEFAULT") AND
        (CMAKE_BUILD_TYPE IN_LIST Seastar_STACK_GUARD_MODES)))
        seastar_supports_flag("-fstack-clash-protection" StackClashProtection_FOUND)
        if(StackClashProtection_FOUND)
            target_compile_options(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
                PUBLIC
                -fstack-clash-protection)
        endif()
        target_compile_definitions(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
            PRIVATE
            SEASTAR_THREAD_STACK_GUARDS)
    endif()

    if((CMAKE_BUILD_TYPE STREQUAL "Dev") OR (CMAKE_BUILD_TYPE STREQUAL "Debug"))
        target_compile_definitions(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
            PUBLIC
            SEASTAR_TYPE_ERASE_MORE)
    endif()

    target_compile_definitions(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
        PRIVATE ${${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}_PRIVATE_COMPILE_DEFINITIONS})

    target_compile_options(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
        PRIVATE ${${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}_PRIVATE_CXX_FLAGS})

    add_library(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}_private INTERFACE)

    target_compile_definitions(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}_private
        INTERFACE ${${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}_PRIVATE_COMPILE_DEFINITIONS})

    target_compile_options(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}_private
        INTERFACE ${${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}_PRIVATE_CXX_FLAGS})

    target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}_private
        INTERFACE ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME})

    #
    # The testing library.
    #

    if(BUILD_TESTS)
        add_library(${CMAKE_WORKSPACE_NAME}_testing
            include/nil/actor/testing/entry_point.hh
            include/nil/actor/testing/exchanger.hh
            include/nil/actor/testing/random.hh
            include/nil/actor/testing/seastar_test.hh
            include/nil/actor/testing/test_case.hh
            include/nil/actor/testing/test_runner.hh
            include/nil/actor/testing/thread_test_case.hh
            src/testing/entry_point.cc
            src/testing/random.cc
            src/testing/seastar_test.cc
            src/testing/test_runner.cc)

        add_library(${CMAKE_WORKSPACE_NAME}::testing ALIAS ${CMAKE_WORKSPACE_NAME}_testing)

        target_compile_definitions(${CMAKE_WORKSPACE_NAME}_testing
            PUBLIC BOOST_TEST_DYN_LINK
            PRIVATE ${${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}_PRIVATE_COMPILE_DEFINITIONS})

        target_compile_options(${CMAKE_WORKSPACE_NAME}_testing
            PRIVATE ${${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}_PRIVATE_CXX_FLAGS})

        target_link_libraries(${CMAKE_WORKSPACE_NAME}_testing
            PUBLIC
            Boost::unit_test_framework
            ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME})

        add_library(${CMAKE_WORKSPACE_NAME}_perf_testing
            src/testing/random.cc
            include/nil/actor/testing/perf_tests.hh
            perf/perf_tests.cc)
        add_library(${CMAKE_WORKSPACE_NAME}::perf_testing ALIAS ${CMAKE_WORKSPACE_NAME}_perf_testing)
        target_compile_definitions(${CMAKE_WORKSPACE_NAME}_perf_testing
            PRIVATE ${${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}_PRIVATE_COMPILE_DEFINITIONS})
        target_compile_options(${CMAKE_WORKSPACE_NAME}_perf_testing
            PRIVATE ${${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}_PRIVATE_CXX_FLAGS})
        target_link_libraries(${CMAKE_WORKSPACE_NAME}_perf_testing PUBLIC ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME})

        cm_deploy(TARGETS ${CMAKE_WORKSPACE_NAME}_perf_testing
            ${CMAKE_WORKSPACE_NAME}_testing
            INCLUDE include
            NAMESPACE ${CMAKE_WORKSPACE_NAME}::)
    endif()

    if(APPLE OR NOT ${CMAKE_TARGET_ARCHITECTURE} STREQUAL ${CMAKE_HOST_SYSTEM_PROCESSOR})
        set_target_properties(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTIES
            XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY "${APPLE_CODE_SIGN_IDENTITY}"
            XCODE_ATTRIBUTE_DEVELOPMENT_TEAM "${CMAKE_XCODE_ATTRIBUTE_DEVELOPMENT_TEAM}")
    endif()

    cm_deploy(TARGETS ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
        INCLUDE include
        NAMESPACE ${CMAKE_WORKSPACE_NAME}::)

    if(BUILD_TESTS)
        add_subdirectory(test)
    endif()
