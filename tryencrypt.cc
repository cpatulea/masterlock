#include <unistd.h>
#include <sys/param.h>
#include "assert.h"
#include "encrypt.h"
#include "secret.h"

int main() {
  initsecret();
  derive();
  initbanner();

  char path[PATH_MAX] = ".";
  encryptall(path);
  return 0;
}
