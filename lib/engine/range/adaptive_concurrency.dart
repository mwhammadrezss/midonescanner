// lib/engine/range/adaptive_concurrency.dart
// Range-specific adaptive concurrency controller (50–1000 workers)
// Separate from the main engine's AdaptiveConcurrencyController (2–24)

class RangeAdaptiveConcurrency {
  int _current;
  int _successStreak = 0;
  int _timeoutStreak = 0;

  static const int _min = 50;
  static const int _max = 1000;
  static const int _scaleUpAfter = 20;
  static const int _scaleDownAfter = 10;
  static const int _scaleUpStep = 50;
  static const int _scaleDownStep = 25;

  RangeAdaptiveConcurrency({int initial = 200})
      : _current = initial.clamp(_min, _max);

  int get current => _current;

  void recordSuccess() {
    _timeoutStreak = 0;
    _successStreak++;
    if (_successStreak >= _scaleUpAfter) {
      _current = (_current + _scaleUpStep).clamp(_min, _max);
      _successStreak = 0;
    }
  }

  void recordTimeout() {
    _successStreak = 0;
    _timeoutStreak++;
    if (_timeoutStreak >= _scaleDownAfter) {
      _current = (_current - _scaleDownStep).clamp(_min, _max);
      _timeoutStreak = 0;
    }
  }

  void recordError() => recordTimeout();

  void set(int value) {
    _current = value.clamp(_min, _max);
    _successStreak = 0;
    _timeoutStreak = 0;
  }

  void reset() {
    _current = 200;
    _successStreak = 0;
    _timeoutStreak = 0;
  }
}
