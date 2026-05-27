// lib/engine/range/deep_result_ranker.dart
// Deep scan result ranker — weighted score for full TLS/tunnel results

class DeepResultRanker {
  /// Weighted 0–100 score for deep-scanned IPs
  double calculate({
    required double latency,
    required double jitter,
    required double reliability,
    double? survivalMs,
    double? speedKBs,
  }) {
    final latencyPart =
        (1000.0 - latency.clamp(0.0, 1000.0)) / 1000.0 * 40.0;
    final jitterPart =
        (200.0 - jitter.clamp(0.0, 200.0)) / 200.0 * 20.0;
    final reliabilityPart = reliability.clamp(0.0, 1.0) * 30.0;
    final survivalPart = survivalMs != null
        ? (survivalMs.clamp(0.0, 20000.0) / 20000.0) * 10.0
        : 0.0;

    return (latencyPart + jitterPart + reliabilityPart + survivalPart)
        .clamp(0.0, 100.0);
  }

  /// S/A/B/C/D/F grading
  String grade(double score) {
    if (score >= 90) return 'S';
    if (score >= 75) return 'A';
    if (score >= 55) return 'B';
    if (score >= 40) return 'C';
    if (score >= 20) return 'D';
    return 'F';
  }
}
