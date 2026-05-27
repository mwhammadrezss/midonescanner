class DeepResultRanker {
  double calculate({
    required double latency,
    required double jitter,
    required double reliability,
  }) {
    return (
      (1000 - latency) * 0.5 +
      (100 - jitter) * 0.2 +
      reliability * 0.3
    );
  }
}