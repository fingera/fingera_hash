#include <fingera/hash/btc.h>

#include <stdlib.h>
#include <time.h>

#include <gtest/gtest.h>

#include "test_utility.h"

TEST(btc, normal) {
  // bitcoin
  test_btc_hash256(
      "cea946542b91ca50e2afecba73cf546ce1383d82668ecb6265f79ffaa07daa49abb43e21"
      "a19c6b2b15c8882b4bc01085a8a5b00168139dcb8f4b2bbe22929ce196d43532898d98a3"
      "b0ea4d63112ba25e724bb50711e3cf55954cf30b4503b73d785253104c2df8c19b5b63e9"
      "2bd6b1ff2573751ec9c508085f3f206c719aa4643776bf425344348cbf63f1450389",
      "52aa8dd6c598d91d580cc446624909e52a076064ffab67a1751f5758c9f76d26");
  test_btc_hash160(
      "cea946542b91ca50e2afecba73cf546ce1383d82668ecb6265f79ffaa07daa49abb43e21"
      "a19c6b2b15c8882b4bc01085a8a5b00168139dcb8f4b2bbe22929ce196d43532898d98a3"
      "b0ea4d63112ba25e724bb50711e3cf55954cf30b4503b73d785253104c2df8c19b5b63e9"
      "2bd6b1ff2573751ec9c508085f3f206c719aa4643776bf425344348cbf63f1450389",
      "FB4037C0906C8AF039020D6B04887BBCE913C6E8");
}

TEST(btc, d64) {
  // bitcoin
  srand(time(0));
  for (int i = 0; i <= 32; ++i) {
    unsigned char in[64 * 32];
    unsigned char out1[32 * 32], out2[32 * 32];
    for (int j = 0; j < 64 * i; ++j) {
      in[j] = (unsigned char)rand();
    }
    for (int j = 0; j < i; ++j) {
      btc_hash256(in + 64 * j, 64, out1 + 32 * j);
    }
    btc_hash256_d64(out2, in, i);
    EXPECT_ZERO(memcmp(out1, out2, 32 * i));
  }
}
