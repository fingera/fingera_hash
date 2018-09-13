/**
 * @brief 比特币中的hash算法
 *
 * @file btc.h
 * @author liuyujun@fingera.cn
 * @date 2018-09-10
 */
#ifndef _FINGERA_HASH_BTC_H_
#define _FINGERA_HASH_BTC_H_

#include <stddef.h>

#include <fingera/hash/ripemd160.h>
#include <fingera/hash/sha2.h>
#include <fingera/header.h>

FINGERA_EXTERN_C_BEGIN

#define btc_hash160_state sha256_state
#define btc_hash160_init sha256_init
#define btc_hash160_update sha256_update
void btc_hash160_final(btc_hash160_state *state, void *hash20);

void btc_hash160(const void *msg, size_t size, void *hash20);
void btc_hash160_se(const void *msg, size_t size, void *hash20);

#define btc_hash256_state sha256_state
#define btc_hash256_init sha256_init
#define btc_hash256_update sha256_update
void btc_hash256_final(btc_hash256_state *state, void *hash32);

void btc_hash256(const void *msg, size_t size, void *hash32);
void btc_hash256_se(const void *msg, size_t size, void *hash32);

void btc_bip32_hash(const void *chain_code, uint32_t child, uint8_t header,
                    const void *data32, void *out64);

void btc_merkletree_hash(void *out, const void *in, size_t blocks);

FINGERA_EXTERN_C_END

#endif  // _FINGERA_HASH_BTC_H_