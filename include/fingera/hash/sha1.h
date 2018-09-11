/**
 * @brief sha1
 *
 * @file sha1.h
 * @author liuyujun@fingera.cn
 * @date 2018-09-10
 */
#ifndef _FINGERA_HASH_SHA1_H_
#define _FINGERA_HASH_SHA1_H_

#include <fingera/hash/block.h>

FINGERA_EXTERN_C_BEGIN

// 声明 sha1_state 类型
BLOCK_DECLARE_STATE(sha1, 64, 5);

void sha1_init(sha1_state *state);
void sha1_update(sha1_state *state, const void *msg, size_t size);
void sha1_final(sha1_state *state, void *hash20);

void sha1(const void *msg, size_t size, void *hash20);
void sha1_se(const void *msg, size_t size, void *hash20);

FINGERA_EXTERN_C_END

#endif  // _FINGERA_HASH_SHA1_H_