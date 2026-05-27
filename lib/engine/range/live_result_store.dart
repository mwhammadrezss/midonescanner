// lib/engine/range/live_result_store.dart
// Real-time result storage with broadcast stream

import 'dart:async';

class RangeScanResult {
  final String ip;
  final double tcpMs;
  final double? tlsMs;
  final double? latencyMs;
  final double? jitterMs;
  final String grade;
  final double score;
  final bool deepScanned;
  final String country;
  final String flag;
  final String? sniUsed;
  final DateTime discoveredAt;

  const RangeScanResult({
    required this.ip,
    required this.tcpMs,
    this.tlsMs,
    this.latencyMs,
    this.jitterMs,
    required this.grade,
    required this.score,
    this.deepScanned = false,
    this.country = '',
    this.flag = '',
    this.sniUsed,
    required this.discoveredAt,
  });

  RangeScanResult copyWith({
    String? grade,
    double? score,
    double? tlsMs,
    double? latencyMs,
    double? jitterMs,
    bool? deepScanned,
    String? country,
    String? flag,
    String? sniUsed,
  }) {
    return RangeScanResult(
      ip: ip,
      tcpMs: tcpMs,
      tlsMs: tlsMs ?? this.tlsMs,
      latencyMs: latencyMs ?? this.latencyMs,
      jitterMs: jitterMs ?? this.jitterMs,
      grade: grade ?? this.grade,
      score: score ?? this.score,
      deepScanned: deepScanned ?? this.deepScanned,
      country: country ?? this.country,
      flag: flag ?? this.flag,
      sniUsed: sniUsed ?? this.sniUsed,
      discoveredAt: discoveredAt,
    );
  }
}

class LiveResultStore {
  final StreamController<RangeScanResult> _controller =
      StreamController<RangeScanResult>.broadcast();
  final List<RangeScanResult> _results = [];

  Stream<RangeScanResult> get stream => _controller.stream;

  /// Unmodifiable snapshot of current results
  List<RangeScanResult> get results => List.unmodifiable(_results);

  int get count => _results.length;

  void add(RangeScanResult r) {
    _results.add(r);
    if (!_controller.isClosed) {
      _controller.add(r);
    }
  }

  /// Top [n] results by score descending
  List<RangeScanResult> topByScore(int n) {
    final sorted = List<RangeScanResult>.from(_results)
      ..sort((a, b) => b.score.compareTo(a.score));
    return sorted.take(n).toList();
  }

  void clear() => _results.clear();

  void dispose() {
    if (!_controller.isClosed) {
      _controller.close();
    }
  }
}
