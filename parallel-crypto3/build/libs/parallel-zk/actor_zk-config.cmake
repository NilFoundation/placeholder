
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
# Library: actor::containers
find_dependency(actor_containers)
# Library: actor::core
find_dependency(actor_core)
# Library: actor::math
find_dependency(actor_math)
# Library: crypto3::algebra
find_dependency(crypto3)
# Library: crypto3::block
find_dependency(crypto3)
# Library: crypto3::hash
find_dependency(crypto3)
# Library: crypto3::multiprecision
find_dependency(crypto3)

include("${CMAKE_CURRENT_LIST_DIR}/actor_zk-targets.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/properties-actor_zk-targets.cmake")
