// lib/engine/soft_blacklist.dart
// p10: softBlacklistEngine — temporarily deprioritize repeatedly-failing IPs

class SoftBlacklist {
  static final SoftBlacklist _i = SoftBlacklist._();
  factory SoftBlacklist() => _i;
  SoftBlacklist._();

  final Map<String, int> _failCount = {};
  final Map<String, DateTime> _deprioritized = {};
  static const int _threshold = 3;
  static const Duration _deprioritizeDuration = Duration(minutes: 5);

  /// Record a failure for [ip].
  void recordFailure(String ip) {
    _failCount[ip] = (_failCount[ip] ?? 0) + 1;
    if ((_failCount[ip] ?? 0) >= _threshold) {
      _deprioritized[ip] = DateTime.now().add(_deprioritizeDuration);
    }
  }

  /// Record a success — clears failure state for [ip].
  void recordSuccess(String ip) {
    _failCount.remove(ip);
    _deprioritized.remove(ip);
  }

  /// Returns true if [ip] is currently deprioritized.
  bool isDeprioritized(String ip) {
    final until = _deprioritized[ip];
    if (until == null) return false;
    if (DateTime.now().isAfter(until)) {
      _deprioritized.remove(ip);
      _failCount.remove(ip);
      return false;
    }
    return true;
  }

  /// How many consecutive failures this IP has.
  int failCount(String ip) => _failCount[ip] ?? 0;

  void clear() {
    _failCount.clear();
    _deprioritized.clear();
  }
}
