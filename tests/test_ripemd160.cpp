#include <fingera/hash/ripemd160.h>

#include <gtest/gtest.h>

#include "test_utility.h"

TEST(ripemd160, normal) {
  // bitcoin
  test_ripmd160("", "9c1185a5c5e9fc54612808977ee8f548b2258d31");
  test_ripmd160("abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
  test_ripmd160("message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36");
  test_ripmd160("secure hash algorithm",
                "20397528223b6a5f4cbc2808aba0464e645544f9");
  test_ripmd160("RIPEMD160 is considered to be safe",
                "a7d78608c7af8a8e728778e81576870734122b66");
  test_ripmd160("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "12a053384a9c0c88e405a06c27dcf49ada62eb2b");
  test_ripmd160("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnop",
                "d7134d2984c6db4078bcec9f39310a07b0413b8c");
  test_ripmd160(
      "For this sample, this 63-byte string will be used as input data",
      "de90dbfee14b63fb5abf27c2ad4a82aaa5f27a11");
  test_ripmd160(
      "This is exactly 64 bytes long, not counting the terminating byte",
      "eda31d51d3a623b81e19eb02e24ff65d27d67b37");
  test_ripmd160(std::string(1000000, 'a').c_str(),
                "52783243c1697bdbe16d37f97f68f08325dc1528");
  // openssl
  test_ripmd160("abcdefghijklmnopqrstuvwxyz",
                "f71c27109c692c1b56bbdceb5b9d2865b3708dbc");
  test_ripmd160(
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
      "b0e20b6e3116640286ed3a87a5713079b21f5189");
  test_ripmd160(
      "123456789012345678901234567890123456789012345678901234567890123456789012"
      "34567890",
      "9b752e45573d4b39f4dbd3323cab82bf63326bfb");
}
