class RetryScheduler {
  bool shouldRetry(int failures) {
    return failures < 3;
  }

  int nextDelayMs(int failures) {
    return 500 * (failures + 1);
  }
}