/**
 * @brief 辅助HASH提供stream-style函数 内部使用
 *
 * @file block_impl.h
 * @author liuyujun@fingera.cn
 * @date 2018-09-10
 */
#ifndef _FINGERA_HASH_BLOCK_IMPL_H_
#define _FINGERA_HASH_BLOCK_IMPL_H_

#define BLOCK_HASH_INIT_IMPLEMENT(HASH_NAME, init_digest)               \
  void HASH_NAME##_init(HASH_NAME##_state *state) {                     \
    assert(sizeof(init_digest) == sizeof(state->digest) && #init_digest \
           "必须是一个数组支持sizeof获取大小且必须一致");               \
    state->chunk_size = 0;                                              \
    state->transformed = 0;                                             \
    memcpy(state->digest, init_digest, sizeof(init_digest));            \
  }

#define BLOCK_HASH_ONE_IMPLEMENT(HASH_NAME)                       \
  void HASH_NAME(const void *msg, size_t size, void *hash) {      \
    HASH_NAME##_state state;                                      \
    HASH_NAME##_init(&state);                                     \
    HASH_NAME##_update(&state, msg, size);                        \
    HASH_NAME##_final(&state, hash);                              \
  }                                                               \
  void HASH_NAME##_se(const void *msg, size_t size, void *hash) { \
    HASH_NAME##_state state;                                      \
    HASH_NAME##_init(&state);                                     \
    HASH_NAME##_update(&state, msg, size);                        \
    HASH_NAME##_final(&state, hash);                              \
    cleanse(&state, sizeof(state));                               \
  }

#define BLOCK_HASH_UPDATE_IMPLEMENT(HASH_NAME)                           \
  void HASH_NAME##_update(HASH_NAME##_state *state, const void *msg,     \
                          size_t size) {                                 \
    const char *buf = (const char *)msg;                                 \
    assert(state->chunk_size < sizeof(state->chunk) && #HASH_NAME        \
           "chunk_size已经满了或者溢出了 错误的状态");                   \
    if (state->chunk_size &&                                             \
        state->chunk_size + size >= sizeof(state->chunk)) {              \
      size_t append_to_full = sizeof(state->chunk) - state->chunk_size;  \
      memcpy(state->chunk + state->chunk_size, buf, append_to_full);     \
      HASH_NAME##_transform(state->digest, state->chunk);                \
      buf += append_to_full;                                             \
      state->transformed += sizeof(state->chunk);                        \
      size -= append_to_full;                                            \
      state->chunk_size = 0;                                             \
    }                                                                    \
    size_t blocks = size / sizeof(state->chunk);                         \
    if (blocks > 0) {                                                    \
      for (size_t i = 0; i < blocks; i++) {                              \
        HASH_NAME##_transform(state->digest, buf);                       \
        buf += sizeof(state->chunk);                                     \
      }                                                                  \
      state->transformed += blocks * sizeof(state->chunk);               \
      size -= blocks * sizeof(state->chunk);                             \
      assert(state->chunk_size == 0 && #HASH_NAME                        \
             "只有chunk_size清空才能整块转换");                          \
    }                                                                    \
    assert(size + state->chunk_size < sizeof(state->chunk) && #HASH_NAME \
           "此时不可能还能组一个chunk");                                 \
    memcpy(state->chunk + state->chunk_size, buf, size);                 \
    state->chunk_size += size;                                           \
  }

#define PAD_SIZE(data_size, block_size, type) \
  (1 +                                        \
   ((((block_size)*2) - (sizeof(type) * 2 + 1 + (data_size))) % (block_size)))

#define BLOCK_HASH_FINAL_IMPLEMENT(HASH_NAME, type)                           \
  void HASH_NAME##_final(HASH_NAME##_state *state, void *hash) {              \
    type *out = (type *)hash;                                                 \
    static const unsigned char pad[sizeof(state->chunk)] = {0x80};            \
    uint8_t size[sizeof(type) * 2];                                           \
    write_size(size, (state->transformed + state->chunk_size) << 3);          \
    HASH_NAME##_update(                                                       \
        state, pad, PAD_SIZE(state->chunk_size, sizeof(state->chunk), type)); \
    HASH_NAME##_update(state, size, sizeof(size));                            \
    assert(state->chunk_size == 0 && #HASH_NAME "final没有清空chunk");        \
    for (size_t i = 0; i < _countof_(state->digest); i++) {                   \
      out[i] = read_hash(state->digest[i]);                                   \
    }                                                                         \
  }

#endif  // _FINGERA_HASH_BLOCK_IMPL_H_