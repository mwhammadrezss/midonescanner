// lib/engine/range/retry_scheduler.dart
// Exponential backoff with jitter for probe retries

import 'dart:math';

class RetryScheduler {
  static const int defaultMax = 3;
  final Random _rng = Random();

  bool shouldRetry(int attempt, int maxAttempts) => attempt < maxAttempts;

  /// Base 300ms * 2^attempt + random 0–200ms jitter, clamped 300–3000ms
  Duration nextDelay(int attempt) {
    final baseMs = (300 * pow(2, attempt)).toInt();
    final jitterMs = _rng.nextInt(200);
    final delayMs = (baseMs + jitterMs).clamp(300, 3000);
    return Duration(milliseconds: delayMs);
  }
}
