// lib/engine/grading_engine.dart
// Weighted scoring: survival 40% + stability 25% + RTT 15% + retransmit 10% + jitter 10%

import '../models/scan_result.dart';

/// Calculate 0-100 score based on the 8-phase pipeline results
double calcScore({
  required bool   survived,
  required int    survivalMs,
  required int    survivalTargetMs,
  required double avgLatencyMs,
  required double jitterMs,
  required int    retransmits,
  required double reliability,   // 0.0–1.0
}) {
  // ── Survival (40%) ───────────────────────────────────────────────────────
  // Full 40 pts if survived ≥ target, partial if partial survival
  final survivalRatio  = survived
      ? 1.0
      : (survivalMs / survivalTargetMs).clamp(0.0, 1.0);
  final survivalScore  = survivalRatio * 40.0;

  // ── Stability / Reliability (25%) ────────────────────────────────────────
  final stabilityScore = reliability * 25.0;

  // ── RTT (15%) ────────────────────────────────────────────────────────────
  // 15 pts at 0 ms, 0 pts at 800 ms
  final rttScore = (1.0 - (avgLatencyMs / 800.0).clamp(0.0, 1.0)) * 15.0;

  // ── Retransmits (10%) ────────────────────────────────────────────────────
  // 0 retransmits = 10 pts, ≥5 = 0 pts
  final retScore = (1.0 - (retransmits / 5.0).clamp(0.0, 1.0)) * 10.0;

  // ── Jitter (10%) ─────────────────────────────────────────────────────────
  // 0 ms jitter = 10 pts, ≥100 ms = 0 pts
  final jitterScore = (1.0 - (jitterMs / 100.0).clamp(0.0, 1.0)) * 10.0;

  final total = survivalScore + stabilityScore + rttScore + retScore + jitterScore;
  return double.parse(total.toStringAsFixed(1));
}

/// Letter grade from score
String calcGradeFromScore(double score, ScanPhase phase) {
  if (phase == ScanPhase.tcpFail ||
      phase == ScanPhase.tlsFail ||
      phase == ScanPhase.handshakeFail) return 'F';
  if (score >= 80) return 'A';
  if (score >= 65) return 'B';
  if (score >= 45) return 'C';
  if (score >= 25) return 'D';
  return 'F';
}
