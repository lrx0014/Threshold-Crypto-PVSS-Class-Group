cmake_minimum_required(VERSION 3.5.1)  # Adjust the version as needed
project(QCLPVSS VERSION 0.0.1 LANGUAGES CXX)  # Change "your_project_name" to your actual project name
set (QCLPVSS_DESCRIPTION "QCLPVSS Implements a PVSS over Class Group Cryptography,
    using the external library BIBYCL")

################################################################################
# Add cmake.utils to the list of CMAKE_MODULE_PATH
################################################################################
set (MODULE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/cmake.utils")
list (APPEND CMAKE_MODULE_PATH "${MODULE_DIR}")

##############################################################################
# Set C++ standard to c++11
##############################################################################
set (CMAKE_CXX_STANDARD 11)
set (CMAKE_CXX_STANDARD_REQUIRED ON)

##############################################################################
# Check version of compiler
##############################################################################
if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "6.1")
    message (FATAL_ERROR "${CMAKE_PROJECT_NAME} requires g++ version >= 6.1")
  endif()
endif ()

##############################################################################
# Set flags and build type (release or debug)
##############################################################################
if (NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message (STATUS "Setting build type to 'Debug' as none was specified.")
  set (CMAKE_BUILD_TYPE "Debug" CACHE STRING "Choose type of build" FORCE)
  set_property (CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release")
  set (CMAKE_CXX_FLAGS_DEBUG "-O3 -g -Wall -Wextra -DDEBUG")
endif ()

# if(NOT MSVC)
#   set (CMAKE_CXX_FLAGS_RELEASE "-O3 -Wall -Wextra -DNDEBUG")
#   set (CMAKE_CXX_FLAGS_DEBUG "-O3 -g -Wall -Wextra -DDEBUG")
# endif()

################################################################################
# Looking for GMP and OpenSSL
################################################################################
find_package (gmp REQUIRED)
find_package (OpenSSL REQUIRED)
find_package (benchmark QUIET) # Google Benchmark (optional; used only for benchmarks)

# Add the bicycl library
add_subdirectory(include/bicycl)

# Add your own source code in the "src" folder
add_subdirectory(src)
add_subdirectory(wrapper)
add_subdirectory(tests)
if (benchmark_FOUND)
  add_subdirectory(benchmarks)
else ()
  message (STATUS "Google Benchmark not found; skipping benchmarks target")
endif ()
add_subdirectory(demo)

# Add any additional targets or configurations here if needed

# Bundle convenience target to gather linkable artifacts for non-CMake consumers
set(DIST_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/dist)
add_custom_target(bundle_static ALL
    DEPENDS pvss_wrapper project
    COMMAND ${CMAKE_COMMAND} -E make_directory ${DIST_ROOT}/lib
    COMMAND ${CMAKE_COMMAND} -E make_directory ${DIST_ROOT}/include
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:pvss_wrapper>
            ${DIST_ROOT}/lib/
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:project>
            ${DIST_ROOT}/lib/
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_CURRENT_SOURCE_DIR}/wrapper/pvss.h
            ${DIST_ROOT}/include/pvss.h
    COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${CMAKE_CURRENT_SOURCE_DIR}/include/bicycl
            ${DIST_ROOT}/include/bicycl
    VERBATIM
)
