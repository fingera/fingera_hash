/**
 * @brief 辅助HASH提供stream-style函数 内部使用
 *
 * @file block.h
 * @author liuyujun@fingera.cn
 * @date 2018-09-10
 */
#ifndef _FINGERA_HASH_BLOCK_H_
#define _FINGERA_HASH_BLOCK_H_

#include <assert.h>
#include <stddef.h>

#include <fingera/header.h>

#define BLOCK_DECLARE_STATE(HASH_NAME, CHUNK_SIZE, DIGEST_SIZE32) \
  typedef struct HASH_NAME##_state_struct {                       \
    uint8_t chunk[CHUNK_SIZE];                                    \
    size_t chunk_size;                                            \
    uint64_t transformed;                                         \
    uint32_t digest[DIGEST_SIZE32];                               \
  } HASH_NAME##_state

#define BLOCK_DECLARE_STATE_64(HASH_NAME, CHUNK_SIZE, DIGEST_SIZE64) \
  typedef struct HASH_NAME##_state_struct {                          \
    uint8_t chunk[CHUNK_SIZE];                                       \
    size_t chunk_size;                                               \
    uint64_t transformed;                                            \
    uint64_t digest[DIGEST_SIZE64];                                  \
  } HASH_NAME##_state

#endif  // _FINGERA_HASH_BLOCK_H_