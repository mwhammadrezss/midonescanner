class AdaptiveConcurrency {
  int currentConcurrency;

  AdaptiveConcurrency({
    this.currentConcurrency = 200,
  });

  void update(int aliveCount) {
    if (aliveCount > 50 && currentConcurrency < 1000) {
      currentConcurrency += 50;
    } else if (aliveCount < 10 && currentConcurrency > 50) {
      currentConcurrency -= 25;
    }
  }
}