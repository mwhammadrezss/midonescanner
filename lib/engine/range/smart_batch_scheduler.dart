// lib/engine/range/smart_batch_scheduler.dart
// Smart batch size scheduling based on live success/timeout rates

import 'dart:math';

class SmartBatchScheduler {
  int _successRate = 100; // 0–100
  int _timeoutRate = 0;   // 0–100

  void update({
    required int successes,
    required int timeouts,
    required int total,
  }) {
    if (total <= 0) return;
    _successRate = (successes / total * 100).round().clamp(0, 100);
    _timeoutRate = (timeouts / total * 100).round().clamp(0, 100);
  }

  /// Recommended next batch size based on current network conditions
  int nextBatchSize(int concurrency) {
    if (_timeoutRate > 50) {
      return max(50, concurrency ~/ 2);
    }
    if (_successRate > 70) {
      return min(concurrency * 2, 1000);
    }
    return concurrency;
  }

  /// Delay between batches — back off when network is stressed
  Duration batchDelay() {
    if (_timeoutRate > 30) return const Duration(milliseconds: 200);
    if (_timeoutRate > 10) return const Duration(milliseconds: 50);
    return Duration.zero;
  }

  int get successRate => _successRate;
  int get timeoutRate => _timeoutRate;
}
