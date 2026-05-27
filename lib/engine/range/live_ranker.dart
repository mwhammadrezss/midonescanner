// lib/engine/range/live_ranker.dart
// Live scoring and ranking for range scan results

import 'fast_probe_engine.dart';
import 'live_result_store.dart';

class LiveRanker {
  /// Weighted score 0–100:
  /// latency 40%, reliability 30%, jitter 20%, tls 10%
  double score(
    FastProbeResult probe, {
    double? tlsMs,
    double? jitter,
    double reliability = 1.0,
  }) {
    final latencyScore =
        (1.0 - (probe.tcpMs / 1000.0).clamp(0.0, 1.0)) * 40.0;
    final reliabilityScore = reliability.clamp(0.0, 1.0) * 30.0;
    final jitterScore = jitter != null
        ? (1.0 - (jitter / 200.0).clamp(0.0, 1.0)) * 20.0
        : 20.0;
    final tlsScore = tlsMs != null
        ? (1.0 - (tlsMs / 3000.0).clamp(0.0, 1.0)) * 10.0
        : 10.0;
    return (latencyScore + reliabilityScore + jitterScore + tlsScore)
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

  /// Sort results by score descending
  List<RangeScanResult> rank(List<RangeScanResult> results) {
    return List<RangeScanResult>.from(results)
      ..sort((a, b) => b.score.compareTo(a.score));
  }
}
