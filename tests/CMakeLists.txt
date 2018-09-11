
add_executable( test_fingera_hash
  test_ripemd160.cpp
  test_sha1.cpp
  test_sha2.cpp
  test_btc.cpp
)

target_link_libraries( test_fingera_hash fingera_hash gtest_main )
add_test(NAME test_fingera_hash COMMAND test_fingera_hash)

if (${BUILD_VALGRIND} STREQUAL "ON")
  find_program(VALGRIND "valgrind")
  if(VALGRIND)
    add_custom_target(valgrind
        COMMAND "${VALGRIND}" --leak-check=full --track-fds=yes $<TARGET_FILE:test_fingera_hash>)
  endif()
endif()
