const int kFileId = 3;
#include <openssl/ec.h>
#include <openssl/objects.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <string.h>
#include <fcntl.h>
#include "assert.h"
#include <unistd.h>
#include "secret.h"
#include "server_public.h"

unsigned char g_rawsecret[16];
BIGNUM* g_secret;
EC_POINT* g_client_public;
BIGNUM* g_shared_secret;
BIGNUM* g_wrapped_key;
char g_bitcoin_address[35];

void hex2bin(const char *hex, unsigned char *bin) {
  int len = 0;
  char h, l;
  while ((h = *hex) && (l = *(hex + 1))) {
    unsigned char n = 0;
#define digit(h, shift) \
      if ('0' <= (h) && (h) <= '9') n |= ((h) - '0') << (shift); \
      else if ('a' <= (h) && (h) <= 'f') n |= ((h) - 'a' + 0xa) << (shift); \
      else if ('A' <= (h) && (h) <= 'F') n |= ((h) - 'A' + 0xa) << (shift); \
      else assert(false);
    digit(h, 4);
    digit(l, 0);
    *bin++ = n;
    hex += 2;
    ++len;
  }
  assert(len == 16);
  assert(h == '\0');
}

void initsecret() {
#ifdef RELEASE
  int fd = open("/dev/urandom", O_RDONLY);
  assert(fd >= 0);
  assert(read(fd, g_rawsecret, sizeof(g_rawsecret)) == sizeof(g_rawsecret));
  assert(close(fd) >= 0);
#else
  hex2bin("0031e6b6fc16c3df9337f72f20d56398", g_rawsecret);
#endif

  g_secret = BN_bin2bn(g_rawsecret, sizeof(g_rawsecret), NULL);
  assert(g_secret);
}

void derive() {
  BN_CTX *ctx = BN_CTX_new();

  EC_GROUP *pgroup = EC_GROUP_new_by_curve_name(NID_secp256k1);
  assert(pgroup);

  //
  // ECDH
  //

  // n % order
  BIGNUM *order = BN_new(), *nmodorder = BN_new();
  assert(EC_GROUP_get_order(pgroup, order, ctx));
  assert(BN_mod(nmodorder, g_secret, order, ctx));
  assert(!BN_is_zero(nmodorder));

  // QA = dA * G
  g_client_public = EC_POINT_new(pgroup);
  assert(EC_POINT_mul(pgroup, g_client_public, nmodorder, NULL, NULL, ctx));

  // shared point = dA * QB
  EC_POINT* server_public = EC_POINT_new(pgroup);
  assert(EC_POINT_oct2point(
      pgroup, server_public,
      g_server_public_bin, sizeof(g_server_public_bin),
      ctx));

  EC_POINT *shared_point = EC_POINT_new(pgroup);
  assert(EC_POINT_mul(
      pgroup, shared_point, NULL, server_public, g_secret, ctx));

  // shared secret = x
  g_shared_secret = BN_new();
  BIGNUM *y = BN_new();
  assert(EC_POINT_get_affine_coordinates_GFp(
      pgroup, shared_point, g_shared_secret, y, ctx));

  // wrapped key = n * shared secret
  g_wrapped_key = BN_new();
  assert(BN_mul(g_wrapped_key, g_secret, g_shared_secret, ctx));

  //
  // Bitcoin
  //
  unsigned char uncomp[65];
  size_t uncomp_len = EC_POINT_point2oct(
      pgroup, g_client_public, POINT_CONVERSION_UNCOMPRESSED,
      uncomp, sizeof(uncomp), ctx);
  assert(uncomp_len > 0);

  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256(uncomp, uncomp_len, hash);

  unsigned char ripemd[1 + RIPEMD160_DIGEST_LENGTH + 4];
  ripemd[0] = 0;  // network ID
  RIPEMD160(hash, SHA256_DIGEST_LENGTH, &ripemd[1]);

  unsigned char hash2[SHA256_DIGEST_LENGTH];
  SHA256(ripemd, 1 + RIPEMD160_DIGEST_LENGTH, hash2);
  SHA256(hash2, SHA256_DIGEST_LENGTH, hash2);

  memcpy(&ripemd[1 + RIPEMD160_DIGEST_LENGTH], hash2, 4);

  BIGNUM *n = BN_bin2bn(ripemd, sizeof(ripemd), NULL);

  BIGNUM *base = BN_new(), *rem = BN_new();
  assert(BN_set_word(base, 58));
  char *p = &g_bitcoin_address[sizeof(g_bitcoin_address)];
  *--p = '\0';
  while (p != g_bitcoin_address) {
    assert(BN_div(n, rem, n, base, ctx));
    unsigned long w = BN_get_word(rem);
    assert(w != 0xffffffffL);
    *--p = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"[w];
  }
}
