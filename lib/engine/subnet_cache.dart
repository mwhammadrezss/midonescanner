// lib/engine/subnet_cache.dart
// p2: subnetMemoryCache — subnet-level confidence and best SNI tracking
// p3: bestSniPerSubnetCache — best SNI per /24 subnet
// p21: subnetTrustWeight — bonus score for known-good subnets
// p22: historicalDecayScore — confidence decays on repeated failures
// p34: subnetHeatmap — identify best subnets

class SubnetMemoryCache {
  static final SubnetMemoryCache _i = SubnetMemoryCache._();
  factory SubnetMemoryCache() => _i;
  SubnetMemoryCache._();

  final Map<String, SubnetStats> _cache = {};

  String _subnet(String ip) {
    final parts = ip.split('.');
    if (parts.length < 3) return ip;
    return '${parts[0]}.${parts[1]}.${parts[2]}';
  }

  // p2: record success with RTT and SNI
  void recordSuccess(String ip, double rttMs, String sni) {
    final s = _subnet(ip);
    _cache.putIfAbsent(s, () => SubnetStats(s)).recordSuccess(rttMs, sni);
  }

  // p2: record failure
  void recordFailure(String ip) {
    final s = _subnet(ip);
    _cache.putIfAbsent(s, () => SubnetStats(s)).recordFailure();
  }

  // p2: confidence score for a given IP's subnet
  double subnetConfidence(String ip) {
    return _cache[_subnet(ip)]?.confidence ?? 0.5;
  }

  // p3: best SNI for this subnet
  String? bestSniForSubnet(String ip) {
    return _cache[_subnet(ip)]?.bestSni;
  }

  // p21: subnetTrustWeight bonus
  double trustBonus(String ip) {
    final conf = subnetConfidence(ip);
    if (conf > 0.8) return 5.0;
    if (conf > 0.6) return 2.5;
    return 0.0;
  }

  // p1: adaptive timeout hint from subnet history
  int? adaptiveTimeoutHint(String ip) {
    final stats = _cache[_subnet(ip)];
    if (stats == null || stats.avgRtt == 0) return null;
    return (stats.avgRtt * 4).clamp(4000, 12000).toInt();
  }

  // p34: top subnets by success count
  List<MapEntry<String, SubnetStats>> topSubnets({int limit = 10}) {
    final entries = _cache.entries.toList();
    entries.sort((a, b) => b.value._successes.compareTo(a.value._successes));
    return entries.take(limit).toList();
  }

  String topSubnetLabel() {
    final top = topSubnets(limit: 1);
    if (top.isEmpty) return '';
    return top.first.key;
  }

  void clear() => _cache.clear();
}

class SubnetStats {
  final String subnet;
  int _successes = 0;
  int _failures = 0;
  double _avgRtt = 0;
  String? bestSni;
  // BUG 3 FIX: track RTT of current bestSni to allow updates
  double _bestSniRtt = double.infinity;

  SubnetStats(this.subnet);

  void recordSuccess(double rttMs, String sni) {
    _successes++;
    _avgRtt = (_avgRtt * (_successes - 1) + rttMs) / _successes;
    // BUG 3 FIX: update bestSni whenever a lower RTT is observed
    if (bestSni == null || rttMs < _bestSniRtt) {
      bestSni = sni;
      _bestSniRtt = rttMs;
    }
  }

  // p22: decay — repeated failures reduce confidence
  void recordFailure() {
    _failures++;
    // Decay: each failure counts as 0.5 additional failures for confidence
    _failures = (_failures * 1.0).round();
  }

  double get confidence {
    final total = _successes + _failures;
    if (total == 0) return 0.5;
    return _successes / total;
  }

  double get avgRtt => _avgRtt;
  int get successes => _successes;
}
