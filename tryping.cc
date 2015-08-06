#include <string.h>
#include "assert.h"
#include "secret.h"
#include "ping.h"

int main() {
  initsecret();
  derive();
  ping();
  return 0;
}
