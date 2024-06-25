int sum100(int *a) {
  int res = 0;
  for (int i = 0; i < 100; ++i) {
    res += a[i];
  }
  return res;
}
