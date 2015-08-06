#include <openssl/bn.h>
#include <openssl/objects.h>
#include <string.h>
#include "assert.h"
#include "secret.h"

int main(int argc, char **argv) {
  assert(argc == 2);
  assert(BN_hex2bn(&g_secret, argv[1]) == (int)strlen(argv[1]));
  assert(BN_num_bytes(g_secret) <= 32);
  derive();

  printf("Secret: 0x%s\n", BN_bn2hex(g_secret));

  EC_GROUP *pgroup = EC_GROUP_new_by_curve_name(NID_secp256k1);
  assert(pgroup);
  printf("Client public: 0x%s\n",
      EC_POINT_point2hex(
          pgroup, g_client_public, POINT_CONVERSION_COMPRESSED, NULL));

  printf("Shared secret: 0x%s\n", BN_bn2hex(g_shared_secret));

  printf("Wrapped key: 0x%s\n", BN_bn2hex(g_wrapped_key));

  printf("Bitcoin address: %s\n", g_bitcoin_address);

  return 0;
}
