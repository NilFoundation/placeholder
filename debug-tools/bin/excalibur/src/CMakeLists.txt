cmake_minimum_required(VERSION 3.21)

set(CMAKE_EXPORT_COMPILE_COMMANDS true)

message (STATUS "PKG_CONFIG_PATH=$ENV{PKG_CONFIG_PATH}")

# get header files; only needed by CMake generators,
# expr.g., for creating proper Xcode projects
set(${CMAKE_PROJECT_NAME}_HEADERS)

set(C3_TARGET "excalibur")

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-pg)
    link_libraries(-pg)
endif()

# list cpp files excluding platform-dependent files
list(APPEND ${CMAKE_PROJECT_NAME}_SOURCES main.cpp)

find_package(Boost COMPONENTS random)
find_package(PkgConfig REQUIRED)

pkg_check_modules(GTK REQUIRED gtk4)

if(NOT GTK_FOUND)
    message(FATAL_ERROR "GTK4 not found!")
endif()

pkg_check_modules(GTKMM REQUIRED gtkmm-4.0)

if (NOT GTKMM_FOUND)
    message(FATAL_ERROR "GTKMM not found!")
endif()

pkg_check_modules(PANGO REQUIRED pango)

if (NOT PANGO_FOUND)
    message(FATAL_ERROR "Pango not found!")
endif()

pkg_check_modules(PANGOMM REQUIRED pangomm-1.4)

if(NOT PANGOMM_FOUND)
    message(FATAL_ERROR "PANGOMM not found!")
endif()

find_package(crypto3 REQUIRED)

include_directories(
    ${GTKMM_INCLUDE_DIRS} ${GTK_INCLUDE_DIRS} ${PANGO_INCLUDE_DIRS} ${PANGOMM_INCLUDE_DIRS})
link_directories(
    ${GTKMM_LIBRARY_DIRS} ${GTK_LIBRARY_DIRS} ${PANGO_LIBRARY_DIRS} ${PANGOMM_LIBRARY_DIRS})

add_executable(${C3_TARGET}
               ${${CMAKE_PROJECT_NAME}_HEADERS}
               ${${CMAKE_PROJECT_NAME}_SOURCES})

set_target_properties(${C3_TARGET} PROPERTIES
                      LINKER_LANGUAGE CXX
                      EXPORT_NAME ${CMAKE_PROJECT_NAME}
                      CXX_STANDARD 23
                      CXX_STANDARD_REQUIRED TRUE)

target_link_directories(
    ${C3_TARGET} PRIVATE ${GTKMM_LIBRARY_DIRS}
    ${GTK_LIBRARY_DIRS} ${PANGO_LIBRARY_DIRS} ${PANGOMM_LIBRARY_DIRS})

target_link_libraries(${C3_TARGET}
                      crypto3::all
                      ${Boost_LIBRARIES}
                      ${GTKMM_LIBRARIES}
                      ${GTK_LIBRARIES}
                      ${PANGOMM_LIBRARIES}
                      ${PANGO_LIBRARIES})
