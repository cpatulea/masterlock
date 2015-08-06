#include <openssl/bn.h>
#include <openssl/ec.h>

extern unsigned char g_rawsecret[16];
extern BIGNUM* g_secret;
extern EC_POINT* g_client_public;
extern BIGNUM* g_shared_secret;
extern BIGNUM* g_wrapped_key;
extern char g_bitcoin_address[35];

void hex2bin(const char *hex, unsigned char *bin);
void initsecret();
void derive();
