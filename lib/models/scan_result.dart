// lib/models/scan_result.dart
import 'probe_result.dart';

class ScanResult {
  final String  ip;
  final double  latencyMs;
  final double  jitterMs;
  final bool    isAlive;
  final String  grade;
  final String  country;
  final String  flag;
  final int     loss;
  final double  reliability;
  final double? bandwidth;

  const ScanResult({
    required this.ip,
    required this.latencyMs,
    required this.jitterMs,
    required this.isAlive,
    required this.grade,
    required this.country,
    required this.flag,
    required this.loss,
    required this.reliability,
    this.bandwidth,
  });
}

class CachedProbe {
  final ProbeResult result;
  final DateTime    createdAt;

  const CachedProbe({
    required this.result,
    required this.createdAt,
  });
}
