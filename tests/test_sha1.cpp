#include <fingera/hash/sha1.h>

#include <gtest/gtest.h>

#include "test_utility.h"

TEST(sha1, normal) {
  // bitcoin
  test_sha1("", "da39a3ee5e6b4b0d3255bfef95601890afd80709");
  test_sha1("abc", "a9993e364706816aba3e25717850c26c9cd0d89d");
  test_sha1("message digest", "c12252ceda8be8994d5fa0290a47231c1d16aae3");
  test_sha1("secure hash algorithm",
            "d4d6d2f0ebe317513bbd8d967d89bac5819c2f60");
  test_sha1("SHA1 is considered to be safe",
            "f2b6650569ad3a8720348dd6ea6c497dee3a842a");
  test_sha1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
  test_sha1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnop",
            "47b172810795699fe739197d1a1f5960700242f1");
  test_sha1("For this sample, this 63-byte string will be used as input data",
            "4f0ea5cd0585a23d028abdc1a6684e5a8094dc49");
  test_sha1("This is exactly 64 bytes long, not counting the terminating byte",
            "fb679f23e7d1ce053313e66e127ab1b444397057");
  test_sha1(std::string(1000000, 'a').c_str(),
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
}
