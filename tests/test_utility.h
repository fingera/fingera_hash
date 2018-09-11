#pragma once

#include <cstddef>

#include <string>

#define EXPECT_ZERO(x) EXPECT_EQ((x), 0)

static const char HEX_STRING_UPPER[16] = {'0', '1', '2', '3', '4', '5',
                                          '6', '7', '8', '9', 'A', 'B',
                                          'C', 'D', 'E', 'F'};

static inline void fingera_to_hex(const void *buf, size_t buf_size, char *str) {
  unsigned char byte;
  unsigned char *bytes = (unsigned char *)buf;
  const char *hex_str = HEX_STRING_UPPER;
  for (size_t i = 0; i < buf_size; i++) {
    byte = bytes[i];
    str[0] = hex_str[byte >> 4];
    str[1] = hex_str[byte & 0xF];
    str += 2;
  }
}

static inline void fingera_hex_dump(const void *buf, size_t buf_size) {
  std::string str;
  str.resize(buf_size * 2);
  fingera_to_hex(buf, buf_size, (char *)str.c_str());
  printf("%s\n", str.c_str());
}

static const unsigned char HEX_MAP[256] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff,
};

static inline size_t fingera_from_hex(const char *str, size_t str_len,
                                      void *buf) {
  unsigned char high, low;
  unsigned char *out = (unsigned char *)buf;
  str_len &= ~(size_t)1;  // 去掉不对齐的
  for (size_t i = 0; i < str_len; i += 2) {
    high = HEX_MAP[(unsigned char)str[i]];
    low = HEX_MAP[(unsigned char)str[i + 1]];
    if (high == 0xFF || low == 0xFF) break;
    *out++ = (high << 4) | low;
  }
  return out - (unsigned char *)buf;
}

typedef void (*HASH_ONE_FUNC)(const void *msg, size_t len, void *hash);
typedef void (*HMAC_HASH_ONE_FUNC)(const void *key, size_t key_len,
                                   const void *msg, size_t len, void *hash);

template <HASH_ONE_FUNC one, HASH_ONE_FUNC one_se, int HASH_SIZE>
static inline void test_hash(const std::string &value,
                             const std::string &hash_hex) {
  char hash[HASH_SIZE];
  EXPECT_EQ(hash_hex.size(), HASH_SIZE * 2);
  EXPECT_EQ(fingera_from_hex(hash_hex.c_str(), hash_hex.size(), hash),
            HASH_SIZE);
  char out_hash[HASH_SIZE];
  one(value.c_str(), value.size(), out_hash);
  EXPECT_ZERO(memcmp(hash, out_hash, HASH_SIZE));
  one_se(value.c_str(), value.size(), out_hash);
  EXPECT_ZERO(memcmp(hash, out_hash, HASH_SIZE));
}

template <HMAC_HASH_ONE_FUNC one, HMAC_HASH_ONE_FUNC one_se, int HASH_SIZE>
static inline void test_hmac_hash(const std::string &key_hex,
                                  const std::string &value_hex,
                                  const std::string &hash_hex) {
  char hash[HASH_SIZE];
  char out_hash[HASH_SIZE];
  std::string key, value;
  EXPECT_EQ(hash_hex.size(), HASH_SIZE * 2);
  EXPECT_EQ(fingera_from_hex(hash_hex.c_str(), hash_hex.size(), hash),
            HASH_SIZE);
  EXPECT_ZERO(key_hex.size() % 2);
  key.resize(key_hex.size() / 2);
  EXPECT_EQ(
      fingera_from_hex(key_hex.c_str(), key_hex.size(), (char *)key.c_str()),
      key.size());
  EXPECT_ZERO(value_hex.size() % 2);
  value.resize(value_hex.size() / 2);
  EXPECT_EQ(fingera_from_hex(value_hex.c_str(), value_hex.size(),
                             (char *)value.c_str()),
            value.size());

  one(key.c_str(), key.size(), value.c_str(), value.size(), out_hash);
  EXPECT_ZERO(memcmp(hash, out_hash, HASH_SIZE));
  one_se(key.c_str(), key.size(), value.c_str(), value.size(), out_hash);
  EXPECT_ZERO(memcmp(hash, out_hash, HASH_SIZE));
}

#define test_ripmd160 test_hash<ripemd160, ripemd160_se, 20>
#define test_sha1 test_hash<sha1, sha1_se, 20>
#define test_sha256 test_hash<sha256, sha256_se, 32>
#define test_sha512 test_hash<sha512, sha512_se, 64>
#define test_hmac_sha256 test_hmac_hash<hmac_sha256, hmac_sha256_se, 32>
#define test_hmac_sha512 test_hmac_hash<hmac_sha512, hmac_sha512_se, 64>
#define test_btc_hash160 test_hash<btc_hash160, btc_hash160_se, 20>
#define test_btc_hash256 test_hash<btc_hash256, btc_hash256_se, 32>
