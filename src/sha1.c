#include <string.h>

#include <fingera/hash/block_impl.h>
#include <fingera/hash/sha1.h>

static void sha1_transform(uint32_t *s, const void *chunk);

static uint32_t sha1_init_digest[5] = {0x67452301UL, 0xEFCDAB89UL, 0x98BADCFEUL,
                                       0x10325476UL, 0xC3D2E1F0UL};

#define write_size writebe64
#define read_hash htobe32

BLOCK_HASH_INIT_IMPLEMENT(sha1, sha1_init_digest);
BLOCK_HASH_UPDATE_IMPLEMENT(sha1);
BLOCK_HASH_FINAL_IMPLEMENT(sha1, uint32_t);
BLOCK_HASH_ONE_IMPLEMENT(sha1);

////////////////////////////////////////////////////////////////////////////////
/********************************************************************/
/* ROL(x, n) cyclically rotates x over n bits to the left */
/* x must be of an unsigned 32 bits type and 0 <= n < 32. */
#define ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define F1(b, c, d) (d) ^ ((b) & ((c) ^ (d)))
#define F2(b, c, d) (b) ^ (c) ^ (d)
#define F3(b, c, d) ((b) & (c)) | ((d) & ((b) | (c)))

#define ROUND(a, b, c, d, e, f, k, w)   \
  (e) += ROL((a), 5) + (f) + (k) + (w); \
  (b) = ROL((b), 30);

/********************************************************************/
static inline uint32_t left(uint32_t x) { return ROL(x, 1); }

static void sha1_transform(uint32_t *s, const void *chunk_data) {
  const char *chunk = (const char *)chunk_data;
  uint32_t a = s[0], b = s[1], c = s[2], d = s[3], e = s[4];
  uint32_t w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15;

  const static uint32_t k1 = 0x5A827999ul;
  const static uint32_t k2 = 0x6ED9EBA1ul;
  const static uint32_t k3 = 0x8F1BBCDCul;
  const static uint32_t k4 = 0xCA62C1D6ul;

  ROUND(a, b, c, d, e, F1(b, c, d), k1, w0 = readbe32(chunk + 0));
  ROUND(e, a, b, c, d, F1(a, b, c), k1, w1 = readbe32(chunk + 4));
  ROUND(d, e, a, b, c, F1(e, a, b), k1, w2 = readbe32(chunk + 8));
  ROUND(c, d, e, a, b, F1(d, e, a), k1, w3 = readbe32(chunk + 12));
  ROUND(b, c, d, e, a, F1(c, d, e), k1, w4 = readbe32(chunk + 16));
  ROUND(a, b, c, d, e, F1(b, c, d), k1, w5 = readbe32(chunk + 20));
  ROUND(e, a, b, c, d, F1(a, b, c), k1, w6 = readbe32(chunk + 24));
  ROUND(d, e, a, b, c, F1(e, a, b), k1, w7 = readbe32(chunk + 28));
  ROUND(c, d, e, a, b, F1(d, e, a), k1, w8 = readbe32(chunk + 32));
  ROUND(b, c, d, e, a, F1(c, d, e), k1, w9 = readbe32(chunk + 36));
  ROUND(a, b, c, d, e, F1(b, c, d), k1, w10 = readbe32(chunk + 40));
  ROUND(e, a, b, c, d, F1(a, b, c), k1, w11 = readbe32(chunk + 44));
  ROUND(d, e, a, b, c, F1(e, a, b), k1, w12 = readbe32(chunk + 48));
  ROUND(c, d, e, a, b, F1(d, e, a), k1, w13 = readbe32(chunk + 52));
  ROUND(b, c, d, e, a, F1(c, d, e), k1, w14 = readbe32(chunk + 56));
  ROUND(a, b, c, d, e, F1(b, c, d), k1, w15 = readbe32(chunk + 60));
  ROUND(e, a, b, c, d, F1(a, b, c), k1, w0 = left(w0 ^ w13 ^ w8 ^ w2));
  ROUND(d, e, a, b, c, F1(e, a, b), k1, w1 = left(w1 ^ w14 ^ w9 ^ w3));
  ROUND(c, d, e, a, b, F1(d, e, a), k1, w2 = left(w2 ^ w15 ^ w10 ^ w4));
  ROUND(b, c, d, e, a, F1(c, d, e), k1, w3 = left(w3 ^ w0 ^ w11 ^ w5));
  ROUND(a, b, c, d, e, F2(b, c, d), k2, w4 = left(w4 ^ w1 ^ w12 ^ w6));
  ROUND(e, a, b, c, d, F2(a, b, c), k2, w5 = left(w5 ^ w2 ^ w13 ^ w7));
  ROUND(d, e, a, b, c, F2(e, a, b), k2, w6 = left(w6 ^ w3 ^ w14 ^ w8));
  ROUND(c, d, e, a, b, F2(d, e, a), k2, w7 = left(w7 ^ w4 ^ w15 ^ w9));
  ROUND(b, c, d, e, a, F2(c, d, e), k2, w8 = left(w8 ^ w5 ^ w0 ^ w10));
  ROUND(a, b, c, d, e, F2(b, c, d), k2, w9 = left(w9 ^ w6 ^ w1 ^ w11));
  ROUND(e, a, b, c, d, F2(a, b, c), k2, w10 = left(w10 ^ w7 ^ w2 ^ w12));
  ROUND(d, e, a, b, c, F2(e, a, b), k2, w11 = left(w11 ^ w8 ^ w3 ^ w13));
  ROUND(c, d, e, a, b, F2(d, e, a), k2, w12 = left(w12 ^ w9 ^ w4 ^ w14));
  ROUND(b, c, d, e, a, F2(c, d, e), k2, w13 = left(w13 ^ w10 ^ w5 ^ w15));
  ROUND(a, b, c, d, e, F2(b, c, d), k2, w14 = left(w14 ^ w11 ^ w6 ^ w0));
  ROUND(e, a, b, c, d, F2(a, b, c), k2, w15 = left(w15 ^ w12 ^ w7 ^ w1));
  ROUND(d, e, a, b, c, F2(e, a, b), k2, w0 = left(w0 ^ w13 ^ w8 ^ w2));
  ROUND(c, d, e, a, b, F2(d, e, a), k2, w1 = left(w1 ^ w14 ^ w9 ^ w3));
  ROUND(b, c, d, e, a, F2(c, d, e), k2, w2 = left(w2 ^ w15 ^ w10 ^ w4));
  ROUND(a, b, c, d, e, F2(b, c, d), k2, w3 = left(w3 ^ w0 ^ w11 ^ w5));
  ROUND(e, a, b, c, d, F2(a, b, c), k2, w4 = left(w4 ^ w1 ^ w12 ^ w6));
  ROUND(d, e, a, b, c, F2(e, a, b), k2, w5 = left(w5 ^ w2 ^ w13 ^ w7));
  ROUND(c, d, e, a, b, F2(d, e, a), k2, w6 = left(w6 ^ w3 ^ w14 ^ w8));
  ROUND(b, c, d, e, a, F2(c, d, e), k2, w7 = left(w7 ^ w4 ^ w15 ^ w9));
  ROUND(a, b, c, d, e, F3(b, c, d), k3, w8 = left(w8 ^ w5 ^ w0 ^ w10));
  ROUND(e, a, b, c, d, F3(a, b, c), k3, w9 = left(w9 ^ w6 ^ w1 ^ w11));
  ROUND(d, e, a, b, c, F3(e, a, b), k3, w10 = left(w10 ^ w7 ^ w2 ^ w12));
  ROUND(c, d, e, a, b, F3(d, e, a), k3, w11 = left(w11 ^ w8 ^ w3 ^ w13));
  ROUND(b, c, d, e, a, F3(c, d, e), k3, w12 = left(w12 ^ w9 ^ w4 ^ w14));
  ROUND(a, b, c, d, e, F3(b, c, d), k3, w13 = left(w13 ^ w10 ^ w5 ^ w15));
  ROUND(e, a, b, c, d, F3(a, b, c), k3, w14 = left(w14 ^ w11 ^ w6 ^ w0));
  ROUND(d, e, a, b, c, F3(e, a, b), k3, w15 = left(w15 ^ w12 ^ w7 ^ w1));
  ROUND(c, d, e, a, b, F3(d, e, a), k3, w0 = left(w0 ^ w13 ^ w8 ^ w2));
  ROUND(b, c, d, e, a, F3(c, d, e), k3, w1 = left(w1 ^ w14 ^ w9 ^ w3));
  ROUND(a, b, c, d, e, F3(b, c, d), k3, w2 = left(w2 ^ w15 ^ w10 ^ w4));
  ROUND(e, a, b, c, d, F3(a, b, c), k3, w3 = left(w3 ^ w0 ^ w11 ^ w5));
  ROUND(d, e, a, b, c, F3(e, a, b), k3, w4 = left(w4 ^ w1 ^ w12 ^ w6));
  ROUND(c, d, e, a, b, F3(d, e, a), k3, w5 = left(w5 ^ w2 ^ w13 ^ w7));
  ROUND(b, c, d, e, a, F3(c, d, e), k3, w6 = left(w6 ^ w3 ^ w14 ^ w8));
  ROUND(a, b, c, d, e, F3(b, c, d), k3, w7 = left(w7 ^ w4 ^ w15 ^ w9));
  ROUND(e, a, b, c, d, F3(a, b, c), k3, w8 = left(w8 ^ w5 ^ w0 ^ w10));
  ROUND(d, e, a, b, c, F3(e, a, b), k3, w9 = left(w9 ^ w6 ^ w1 ^ w11));
  ROUND(c, d, e, a, b, F3(d, e, a), k3, w10 = left(w10 ^ w7 ^ w2 ^ w12));
  ROUND(b, c, d, e, a, F3(c, d, e), k3, w11 = left(w11 ^ w8 ^ w3 ^ w13));
  ROUND(a, b, c, d, e, F2(b, c, d), k4, w12 = left(w12 ^ w9 ^ w4 ^ w14));
  ROUND(e, a, b, c, d, F2(a, b, c), k4, w13 = left(w13 ^ w10 ^ w5 ^ w15));
  ROUND(d, e, a, b, c, F2(e, a, b), k4, w14 = left(w14 ^ w11 ^ w6 ^ w0));
  ROUND(c, d, e, a, b, F2(d, e, a), k4, w15 = left(w15 ^ w12 ^ w7 ^ w1));
  ROUND(b, c, d, e, a, F2(c, d, e), k4, w0 = left(w0 ^ w13 ^ w8 ^ w2));
  ROUND(a, b, c, d, e, F2(b, c, d), k4, w1 = left(w1 ^ w14 ^ w9 ^ w3));
  ROUND(e, a, b, c, d, F2(a, b, c), k4, w2 = left(w2 ^ w15 ^ w10 ^ w4));
  ROUND(d, e, a, b, c, F2(e, a, b), k4, w3 = left(w3 ^ w0 ^ w11 ^ w5));
  ROUND(c, d, e, a, b, F2(d, e, a), k4, w4 = left(w4 ^ w1 ^ w12 ^ w6));
  ROUND(b, c, d, e, a, F2(c, d, e), k4, w5 = left(w5 ^ w2 ^ w13 ^ w7));
  ROUND(a, b, c, d, e, F2(b, c, d), k4, w6 = left(w6 ^ w3 ^ w14 ^ w8));
  ROUND(e, a, b, c, d, F2(a, b, c), k4, w7 = left(w7 ^ w4 ^ w15 ^ w9));
  ROUND(d, e, a, b, c, F2(e, a, b), k4, w8 = left(w8 ^ w5 ^ w0 ^ w10));
  ROUND(c, d, e, a, b, F2(d, e, a), k4, w9 = left(w9 ^ w6 ^ w1 ^ w11));
  ROUND(b, c, d, e, a, F2(c, d, e), k4, w10 = left(w10 ^ w7 ^ w2 ^ w12));
  ROUND(a, b, c, d, e, F2(b, c, d), k4, w11 = left(w11 ^ w8 ^ w3 ^ w13));
  ROUND(e, a, b, c, d, F2(a, b, c), k4, w12 = left(w12 ^ w9 ^ w4 ^ w14));
  ROUND(d, e, a, b, c, F2(e, a, b), k4, left(w13 ^ w10 ^ w5 ^ w15));
  ROUND(c, d, e, a, b, F2(d, e, a), k4, left(w14 ^ w11 ^ w6 ^ w0));
  ROUND(b, c, d, e, a, F2(c, d, e), k4, left(w15 ^ w12 ^ w7 ^ w1));

  s[0] += a;
  s[1] += b;
  s[2] += c;
  s[3] += d;
  s[4] += e;
}