/**
 * @brief ripemd160
 *
 * @file ripemd160.h
 * @author liuyujun@fingera.cn
 * @date 2018-09-10
 */
#ifndef _FINGERA_HASH_RIPEMD160_H_
#define _FINGERA_HASH_RIPEMD160_H_

#include <fingera/hash/block.h>

FINGERA_EXTERN_C_BEGIN

// 声明 ripemd160_state 类型
BLOCK_DECLARE_STATE(ripemd160, 64, 5);

void ripemd160_init(ripemd160_state *state);
void ripemd160_update(ripemd160_state *state, const void *msg, size_t size);
void ripemd160_final(ripemd160_state *state, void *hash20);

void ripemd160(const void *msg, size_t size, void *hash20);
void ripemd160_se(const void *msg, size_t size, void *hash20);

FINGERA_EXTERN_C_END

#endif  // _FINGERA_HASH_RIPEMD160_H_