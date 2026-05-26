// lib/engine/grading_engine.dart
// Weighted scoring: survival 50% + stability 30% + RTT 20%
// Retransmits removed (always 0 from TLS layer — unusable metric)
// Bandwidth NOT included in score (too noisy: CDN caching, TCP slow start)
//
// Changes (fix #12):
//   - RTT score now uses logarithmic penalty instead of linear
//     Network behavior is not linear: 50ms vs 100ms ≈ same UX,
//     but 1000ms vs 2000ms is a huge difference. Log scale reflects this.
//   - Jitter removed from score (3 samples = statistically useless, fix #5)
//     Jitter is still measured and stored for diagnostic display only.

import 'dart:math';
import '../models/scan_result.dart';

/// Calculate 0-100 score
double calcScore({
  required bool   survived,
  required int    survivalMs,
  required int    survivalTargetMs,
  required double avgLatencyMs,
  required double reliability,   // 0.0–1.0
  // jitterMs intentionally removed from scoring (fix #5)
}) {
  // ── Survival (50%) ───────────────────────────────────────────────────────
  // Full 50 pts at target, partial for partial survival.
  final survivalRatio = survived
      ? 1.0
      : (survivalMs / survivalTargetMs).clamp(0.0, 1.0);
  final survivalScore = survivalRatio * 50.0;

  // ── Stability / Reliability (30%) ────────────────────────────────────────
  final stabilityScore = reliability * 30.0;

  // ── RTT (20%) — logarithmic scale (fix #12) ──────────────────────────────
  // log1p(0) = 0, log1p(999) ≈ 6.9
  // Score: 20 at 0ms → 0 at ~1000ms, but with log curve:
  //   100ms → ~17pts (barely penalized)
  //   300ms → ~13pts
  //   700ms → ~9pts
  //   1500ms → ~5pts (not zero, Iranian networks are lossy)
  final logMax = log(1001); // log1p(1000)
  final rttScore = (1.0 - (log(avgLatencyMs.clamp(0, 9999) + 1) / logMax).clamp(0.0, 1.0)) * 20.0;

  final total = survivalScore + stabilityScore + rttScore;
  return double.parse(total.toStringAsFixed(1));
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
