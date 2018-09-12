cmake_minimum_required(VERSION 3.5)

option(BUILD_TESTING "Enable test (depends on googletest)." OFF)
option(BUILD_VALGRIND "Enable valgrind (depends on BUILD_TESTING)." OFF)
option(BUILD_EXTERNAL "Enable build external" ON)

if (${BUILD_EXTERNAL} STREQUAL "ON")
  add_subdirectory(external)
endif()

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
