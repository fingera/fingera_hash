cmake_minimum_required(VERSION 3.5)

option(BUILD_TESTING "Enable test (depends on googletest)." OFF)
option(BUILD_VALGRIND "Enable valgrind (depends on BUILD_TESTING)." OFF)

if ("${CMAKE_C_COMPILER_ID}" STREQUAL "MSVC")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /utf-8")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /utf-8")
endif()

add_subdirectory(external)

add_library(fingera_hash
  src/ripemd160.c
  src/sha1.c
  src/sha2.c
  src/btc.c
)

target_link_libraries(fingera_hash fingera_header)
target_include_directories(fingera_hash
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

if (${BUILD_TESTING} STREQUAL "ON")
  include(CTest)
  add_subdirectory(tests)
endif()