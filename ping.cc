const int kFileId = 2;
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ec.h>
#include <openssl/objects.h>
#include "assert.h"
#include "secret.h"
#include "version.h"

const char *g_host = "llvxvfttpgkvievb.onion.city";
const char *g_port = "80";

void ping() {
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_NUMERICSERV;

  struct addrinfo *result;
  assert(getaddrinfo(g_host, g_port, NULL, &result) == 0);
  assert(result != NULL);

  int fd = socket(result->ai_family, SOCK_STREAM, 0);
  assert(fd >= 0);

  assert(connect(fd, result->ai_addr, result->ai_addrlen) >= 0);

  // ping
  BN_CTX *ctx = BN_CTX_new();
  EC_GROUP *pgroup = EC_GROUP_new_by_curve_name(NID_secp256k1);
  char buf[1024];
  sprintf(buf, 
      "GET /ping?cp=%s&wk=%s HTTP/1.0\r\n"
      "User-Agent: masterlock (%s)\r\n"
      "Host: %s\r\n"
      "Cache-Control: private, max-age=0, no-cache\r\n"
      "x-onioncity: please-refresh\r\n"
      "Connection: close\r\n"
      "\r\n",
      EC_POINT_point2hex(
          pgroup, g_client_public, POINT_CONVERSION_COMPRESSED, ctx),
      BN_bn2hex(g_wrapped_key),
      kVersion, g_host);
  assert(write(fd, buf, strlen(buf)) == (ssize_t)strlen(buf));
  assert(shutdown(fd, SHUT_WR) >= 0);

  ssize_t len = read(fd, buf, sizeof(buf) - 1);
  assert(len > 0);
  buf[len] = 0;

  assert(strstr(buf, "200 OK"));

  len = read(fd, buf, 1);
  assert(len == 0);

  assert(close(fd) >= 0);
}
