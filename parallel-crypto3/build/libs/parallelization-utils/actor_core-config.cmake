
include(CMakeFindDependencyMacro)
# Library: Boost::container
find_dependency(boost_container 1.83.0)
# Library: Boost::json
find_dependency(boost_json 1.83.0)
# Library: Boost::filesystem
find_dependency(boost_filesystem 1.83.0)
# Library: Boost::log
find_dependency(boost_log 1.83.0)
# Library: Boost::log_setup
find_dependency(boost_log_setup 1.83.0)
# Library: Boost::program_options
find_dependency(boost_program_options 1.83.0)
# Library: Boost::thread
find_dependency(boost_thread 1.83.0)
# Library: Boost::system
find_dependency(boost_system 1.83.0)
# Library: Boost::unit_test_framework
find_dependency(boost_unit_test_framework 1.83.0)

include("${CMAKE_CURRENT_LIST_DIR}/actor_core-targets.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/properties-actor_core-targets.cmake")
