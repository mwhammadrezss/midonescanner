// lib/engine/grading_engine.dart
// Weighted scoring: survival 50% + stability 30% + RTT 20%
// Retransmits removed (always 0 from TLS layer — unusable metric)
// Bandwidth NOT included in score (too noisy: CDN caching, TCP slow start)
//
// Changes:
//   - p19: RTT score uses logarithmic penalty instead of linear
//   - p20: confidenceScore — reliability + sample count + survival
//   - p23: instabilityPenalty — jitter-based penalty
//   - p24: realUsabilityIndex — combined survival + reliability + handshake speed
//   - p21: subnetTrustWeight applied as bonus
//   - Jitter removed from main score (too few samples)

import 'dart:math';
import '../models/scan_result.dart';

/// p23: Instability penalty based on jitter.
double instabilityPenalty(double jitterMs) {
  if (jitterMs < 50) return 0;
  if (jitterMs < 100) return 2;
  if (jitterMs < 200) return 5;
  return 10;
}

/// Calculate 0-100 score
/// p21: subnetTrustBonus added as bonus points
double calcScore({
  required bool   survived,
  required int    survivalMs,
  required int    survivalTargetMs,
  required double avgLatencyMs,
  required double reliability,   // 0.0–1.0
  double subnetTrustBonus = 0.0, // p21: subnet trust weight bonus
  // jitterMs intentionally removed from scoring (too few samples)
}) {
  // ── Survival (50%) ───────────────────────────────────────────────────────
  // Full 50 pts at target, partial for partial survival.
  final survivalRatio = survived
      ? 1.0
      : (survivalMs / survivalTargetMs).clamp(0.0, 1.0);
  final survivalScore = survivalRatio * 50.0;

  // ── Stability / Reliability (30%) ────────────────────────────────────────
  final stabilityScore = reliability * 30.0;

  // ── p19: RTT (20%) — logarithmic scale ───────────────────────────────────
  // log1p(0) = 0, log1p(999) ≈ 6.9
  // Score: 20 at 0ms → 0 at ~1000ms, but with log curve:
  //   100ms → ~17pts (barely penalized)
  //   300ms → ~13pts
  //   700ms → ~9pts
  //   1500ms → ~5pts (not zero, Iranian networks are lossy)
  final logMax = log(1001); // log1p(1000)
  final rttScore =
      (1.0 - (log(avgLatencyMs.clamp(0, 9999) + 1) / logMax).clamp(0.0, 1.0)) *
          20.0;

  final raw = survivalScore + stabilityScore + rttScore + subnetTrustBonus;
  final total = raw.clamp(0.0, 100.0);
  return double.parse(total.toStringAsFixed(1));
}

/// p20: confidenceScore — how reliable/trustworthy this result is.
/// Separate from usability score.
double calcConfidenceScore({
  required double reliability,
  required int sampleCount,
  required int survivalMs,
}) {
  // More samples = more confidence
  final sampleFactor = (sampleCount / 5.0).clamp(0.0, 1.0);
  final stabilityFactor = (survivalMs / 20000.0).clamp(0.0, 1.0);
  final score = (reliability * 0.5 + sampleFactor * 0.3 + stabilityFactor * 0.2) * 100;
  return double.parse(score.toStringAsFixed(1));
}

/// p24: realUsabilityIndex — survival + reconnect success + handshake speed.
double calcRealUsabilityIndex({
  required bool survived,
  required int survivalMs,
  required double reliability,
  required double tlsHandshakeMs,
}) {
  final survivalScore =
      survived ? (survivalMs / 20000.0).clamp(0.0, 1.0) : 0.0;
  final reliabilityScore = reliability;
  // Handshake speed: 0ms=1.0, 3000ms=0.0
  final hsScore = (1.0 - (tlsHandshakeMs / 3000.0)).clamp(0.0, 1.0);
  final result =
      (survivalScore * 0.5 + reliabilityScore * 0.3 + hsScore * 0.2) * 100;
  return double.parse(result.toStringAsFixed(1));
}

/// Soft tier classification — permissive, not elitist
IpTier calcTier(int survivalMs, ScanPhase phase) {
  if (phase == ScanPhase.tcpFail ||
      phase == ScanPhase.tlsFail ||
      phase == ScanPhase.handshakeFail) {
    return IpTier.dead;
  }
  if (phase == ScanPhase.stabilityFail) return IpTier.dead;
  // TLS ok but no survival at all
  if (survivalMs < 3000) return IpTier.weak;
  // Short survival — still usable for ShirKhorshid
  if (survivalMs >= 20000) return IpTier.excellent;
  if (survivalMs >= 10000) return IpTier.good;
  if (survivalMs >=  5000) return IpTier.usable;
  return IpTier.weak;
}

/// Letter grade from score
String calcGradeFromScore(double score, ScanPhase phase) {
  if (phase == ScanPhase.tcpFail ||
      phase == ScanPhase.tlsFail ||
      phase == ScanPhase.handshakeFail ||
      phase == ScanPhase.stabilityFail) return 'F';
  if (score >= 80) return 'A';
  if (score >= 60) return 'B';
  if (score >= 40) return 'C';
  if (score >= 20) return 'D';
  return 'F';
}
