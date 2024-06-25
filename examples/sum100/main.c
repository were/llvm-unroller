#include <stdlib.h>
#include <assert.h>

#include "kernel.h"

int a[100];

int main(int argc, char **argv) {
  int ref = 0;
  for (int i = 0; i < 100; ++i) {
    a[i] = rand() % 1000;
    ref += a[i];
  }
  int res = sum100(a);
  assert(res == ref);
  return 0;
}
