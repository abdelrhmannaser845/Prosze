cmake_minimum_required(VERSION 3.16)

project(prosze
    VERSION 1.0.0
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(prosze prosze/Application.cpp)

include(CTest)

if(BUILD_TESTING)
    add_executable(prosze_tests prosze/tests/ApplicationTests.cpp)
    add_test(NAME prosze_tests COMMAND prosze_tests WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
endif()
