/**
 * @brief sha2: 256 hmac256 512 hmac512
 *
 * @file sha2.h
 * @author liuyujun@fingera.cn
 * @date 2018-09-10
 */
#ifndef _FINGERA_HASH_SHA2_H_
#define _FINGERA_HASH_SHA2_H_

#include <fingera/hash/block.h>

FINGERA_EXTERN_C_BEGIN

////////////////////////////////////////////////////////////////////////////////
// 声明 sha256_state 类型
BLOCK_DECLARE_STATE(sha256, 64, 8);

void sha256_init(sha256_state *state);
void sha256_update(sha256_state *state, const void *msg, size_t size);
void sha256_final(sha256_state *state, void *hash32);

void sha256(const void *msg, size_t size, void *hash32);
void sha256_se(const void *msg, size_t size, void *hash32);

typedef struct _hmac_sha256_state {
  sha256_state inner;
  sha256_state outter;
} hmac_sha256_state;

void hmac_sha256_init(hmac_sha256_state *state, const void *key, size_t size);
void hmac_sha256_update(hmac_sha256_state *state, const void *msg, size_t size);
void hmac_sha256_final(hmac_sha256_state *state, void *hash32);

void hmac_sha256(const void *key, size_t key_size, const void *msg, size_t size,
                 void *hash32);
void hmac_sha256_se(const void *key, size_t key_size, const void *msg,
                    size_t size, void *hash32);

////////////////////////////////////////////////////////////////////////////////
// 声明 sha512_state 类型
BLOCK_DECLARE_STATE_64(sha512, 128, 8);

void sha512_init(sha512_state *state);
void sha512_update(sha512_state *state, const void *msg, size_t size);
void sha512_final(sha512_state *state, void *hash64);

void sha512(const void *msg, size_t size, void *hash64);
void sha512_se(const void *msg, size_t size, void *hash64);

typedef struct _hmac_sha512_state {
  sha512_state inner;
  sha512_state outter;
} hmac_sha512_state;

void hmac_sha512_init(hmac_sha512_state *state, const void *key, size_t size);
void hmac_sha512_update(hmac_sha512_state *state, const void *msg, size_t size);
void hmac_sha512_final(hmac_sha512_state *state, void *hash64);

void hmac_sha512(const void *key, size_t key_size, const void *msg, size_t size,
                 void *hash64);
void hmac_sha512_se(const void *key, size_t key_size, const void *msg,
                    size_t size, void *hash64);

FINGERA_EXTERN_C_END

#endif  // _FINGERA_HASH_SHA2_H_