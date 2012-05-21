# ---------------------------------------------------------------------------#
# ------------------------------- CMake -------------------------------------#
# ---------------------------------------------------------------------------#

# minimum supported cmake version
cmake_minimum_required(VERSION 2.6)

# identify the project and programming language
project(eyeballs C)

# compiler flags passed as arguments 
add_definitions(-Wall -Werror -std=c99)

# set output directories for libraries and executables
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

# specify the TARGET executable
add_executable(dns ${CMAKE_SOURCE_DIR}/src/dns.c)

# add external link libraries
target_link_libraries(dns resolv)

# ---------------------------------------------------------------------------#
