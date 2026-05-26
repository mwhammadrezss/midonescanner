// lib/models/scan_result.dart

/// Phase labels for pipeline
enum ScanPhase {
  tcpFail,
  tlsFail,
  handshakeFail,
  completionFail,
  survivalFail,
  stabilityFail,
  dpiFail,
  passed,
}

/// Soft usability classification — permissive, not elitist
enum IpTier {
  excellent,  // 20s+ survived
  good,       // 10s+ survived
  usable,     // 5s+ survived (TLS ok, short survival)
  weak,       // TLS handshake only, no survival
  dead,       // TCP/TLS fail
}

class ScanResult {
  final String    ip;
  final double    latencyMs;     // TCP + TLS combined (user-facing)
  final double    jitterMs;
  final bool      isAlive;
  final String    grade;
  final String    country;
  final String    flag;
  final int       loss;
  final double    reliability;

  // ── Survival fields ──────────────────────────────────────────────────────
  final double?   score;
  final int?      survivalMs;
  final int       retransmits;
  final ScanPhase phase;
  final IpTier    tier;

  // ── Bandwidth & SNI fields ───────────────────────────────────────────────
  final double?   speedKBs;
  final String?   sniUsed;

  // ── Diagnostic breakdown (separate TCP/TLS latency) ──────────────────────
  final double?   tcpLatencyMs;
  final double?   tlsHandshakeMs;

  // ── p16: DPI suspicion score (0.0 = clean, 1.0 = very likely DPI) ────────
  final double    dpiSuspicion;

  // ── p20: Confidence score — how trustworthy is this result ───────────────
  final double?   confidenceScore;

  // ── p24: Real usability index — survival + reliability + handshake speed ─
  final double?   realUsabilityIndex;

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
    this.score,
    this.survivalMs,
    this.retransmits = 0,
    this.phase = ScanPhase.tcpFail,
    this.tier  = IpTier.dead,
    this.speedKBs,
    this.sniUsed,
    this.tcpLatencyMs,
    this.tlsHandshakeMs,
    this.dpiSuspicion = 0.0,
    this.confidenceScore,
    this.realUsabilityIndex,
  });

  String get phaseLabel {
    switch (phase) {
      case ScanPhase.tcpFail:        return 'TCP Fail';
      case ScanPhase.tlsFail:        return 'TLS Fail';
      case ScanPhase.handshakeFail:  return 'Handshake';
      case ScanPhase.completionFail: return 'TLS Incomplete';
      case ScanPhase.survivalFail:   return 'Weak';
      case ScanPhase.stabilityFail:  return 'Unstable';
      case ScanPhase.dpiFail:        return 'DPI Killed';
      case ScanPhase.passed:         return 'Passed ✓';
    }
  }

  String get tierLabel {
    switch (tier) {
      case IpTier.excellent: return '★★★ Excellent';
      case IpTier.good:      return '★★ Good';
      case IpTier.usable:    return '★ Usable';
      case IpTier.weak:      return 'Weak';
      case IpTier.dead:      return 'Dead';
    }
  }
}
