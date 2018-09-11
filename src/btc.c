#include <fingera/hash/block_impl.h>
#include <fingera/hash/btc.h>

void btc_hash160_final(btc_hash160_state *state, void *hash20) {
  ripemd160_state rip;
  ripemd160_init(&rip);
  sha256_final(state, rip.chunk);
  rip.chunk_size = 32;
  ripemd160_final(&rip, hash20);
  cleanse(rip.chunk, 32);
}

void btc_hash256_final(btc_hash256_state *state, void *hash32) {
  sha256_state sha;
  sha256_init(&sha);
  sha256_final(state, sha.chunk);
  sha.chunk_size = 32;
  sha256_final(&sha, hash32);
  cleanse(sha.chunk, 32);
}

BLOCK_HASH_ONE_IMPLEMENT(btc_hash160);
BLOCK_HASH_ONE_IMPLEMENT(btc_hash256);

void btc_bip32_hash(const void *chain_code, uint32_t child, uint8_t header,
                    const void *data32, void *out64) {
  char buffer[1 + 32 + 4];
  char *ptr = buffer;
  memcpy(ptr, &header, 1);
  ptr++;
  memcpy(ptr, data32, 32);
  ptr += 32;
  writebe32(ptr, child);
  hmac_sha512_se(chain_code, 32, buffer, sizeof(buffer), out64);
  cleanse(buffer, sizeof(buffer));
}