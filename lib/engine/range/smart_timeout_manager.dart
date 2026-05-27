// lib/engine/range/smart_timeout_manager.dart
// Adaptive timeout based on rolling RTT history (p90 of last 20 samples)

import 'dart:math';

class SmartTimeoutManager {
  final List<double> _rtts = [];
  static const int _windowSize = 20;
  static const int _minMs = 800;
  static const int _maxMs = 4000;
  static const int _defaultMs = 1200;

  void add(double rttMs) {
    _rtts.add(rttMs);
    if (_rtts.length > _windowSize) {
      _rtts.removeAt(0);
    }
  }

  /// p90 of recent RTTs. Min 800ms, Max 4000ms. Default 1200ms if no samples.
  int get timeoutMs {
    if (_rtts.isEmpty) return _defaultMs;
    final sorted = List<double>.from(_rtts)..sort();
    final p90idx = ((sorted.length * 0.9).ceil() - 1).clamp(0, sorted.length - 1);
    final p90 = sorted[p90idx];
    // Add 20% headroom above p90
    return (p90 * 1.2).round().clamp(_minMs, _maxMs);
  }

  /// Half of timeoutMs, min 400ms — used for the fast TCP-only probe stage
  int get fastTimeoutMs => max(400, timeoutMs ~/ 2);

  void reset() => _rtts.clear();
}
