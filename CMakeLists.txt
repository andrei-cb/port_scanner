cmake_minimum_required(VERSION 3.1.0)
project(port_scanner)

find_package(Boost REQUIRED system)
include_directories(${Boost_INCLUDE_DIR})

set(CMAKE_CXX_STANDARD 20)

#add_subdirectory(quill)
add_subdirectory(cxxopts)
#add_subdirectory(json)

add_executable(port_scanner main.cpp)
target_link_libraries(port_scanner PRIVATE ${Boost_LIBRARIES} PRIVATE cxxopts::cxxopts)
