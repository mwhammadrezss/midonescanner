class SmartBatchScheduler {
  int nextBatchSize({
    required int successRate,
    required int failures,
  }) {
    if (failures > 20) {
      return 50;
    }

    if (successRate > 70) {
      return 500;
    }

    return 200;
  }
}