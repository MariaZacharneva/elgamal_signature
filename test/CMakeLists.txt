cmake_minimum_required(VERSION 3.28)
project(GoogleTest)

set(GOOGLETEST_VERSION 1.9.0)
# 'lib' is the folder with Google Test sources
add_subdirectory(lib/googletest-1.15.2/googletest)
include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})
include_directories(lib/googletest/include)

# 'Google_Tests_run' is the target name
# 'Test1_EmptyTag.cpp Test2_TagWithText.cpp' are source files with tests
add_executable(GoogleTest_run tools_test.cpp elgamal_test.cpp
        ../src/cryptography/cryptography.cpp
        ../src/cryptography/cryptography.h
        ../src/cryptography/tools.cpp
        ../src/cryptography/tools.h)
target_link_libraries(GoogleTest_run gtest gtest_main)