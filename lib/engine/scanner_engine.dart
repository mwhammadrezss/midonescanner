// lib/engine/scanner_engine.dart
// ─── Android TLS Tunnel Survivability Scanner ────────────────────────────────
import 'dart:async';
import 'dart:math';
import '../models/scan_result.dart';
import '../geo/geoip.dart';
import 'probe_engine.dart';
import 'tunnel_engine.dart';
import 'grading_engine.dart';
import 'concurrency_engine.dart';
import '../utils/stats_utils.dart';

export '../models/scan_result.dart';
export '../utils/ip_utils.dart';

const shiroSni = kShiroSni;

enum ScanMode { normal, deep }

// Survival targets
const _survivalNormal = 20000;  // 20s
const _survivalDeep   = 20000;  // 20s (reduced from 30s — smarter not longer, fix #10)

// Module-level cancellation passthrough — set by runScanningEngine
// so that tunnelSurvivalTest inside _scanWithSni can check it.
bool Function()? _currentIsCancelled;

// ─── scanOneIp ───────────────────────────────────────────────────────────────
Future<ScanResult> scanOneIp(
  String ip, {
  ScanMode mode        = ScanMode.normal,
  List<String>? snis,
  bool Function()? isCancelled,
}) async {
  _currentIsCancelled = isCancelled;
  final (country, flag) = GeoIPOffline().lookupFull(ip);
  final survivalTarget  = mode == ScanMode.deep ? _survivalDeep : _survivalNormal;
  final repeats         = mode == ScanMode.deep ? 5 : 3;

  // Deep mode SNI order: use caller's list or fall back to priority-ordered presets
  // Fix #4: SNIs are now priority-ordered in kDeepSniPresets (Google first)
  final effectiveSnis   = (mode == ScanMode.deep && snis != null && snis.isNotEmpty)
      ? snis
      : (mode == ScanMode.deep ? kDeepSniPresets : [kShiroSni]);

  ScanResult dead(ScanPhase phase) => ScanResult(
    ip: ip, latencyMs: 9999, jitterMs: 0,
    isAlive: false, grade: 'F', country: country, flag: flag,
    loss: 100, reliability: 0,
    score: 0, survivalMs: 0, retransmits: 0,
    phase: phase, tier: IpTier.dead,
  );

  // ─── NORMAL MODE ─────────────────────────────────────────────────────────
  if (mode == ScanMode.normal) {
    return await _scanWithSni(ip, kShiroSni, survivalTarget, repeats,
        country: country, flag: flag, dead: dead);
  }

  // ─── DEEP MODE — try each SNI with family early-exit (fix #4) ────────────
  ScanResult? bestResult;
  bool googleFamilyPassed = false;
  bool cloudflareFamilyPassed = false;

  for (final sni in effectiveSnis) {
    // Skip remaining Google-family if one already passed (fix #4)
    if (googleFamilyPassed && kSniGoogleFamily.contains(sni)) continue;
    // Skip remaining Cloudflare-family if one already passed
    if (cloudflareFamilyPassed && kSniCloudflareFamily.contains(sni)) continue;

    final candidate = await _scanWithSni(ip, sni, survivalTarget, repeats,
        country: country, flag: flag, dead: dead);

    // Track family passes for early-exit
    if (candidate.tier != IpTier.dead && candidate.tier != IpTier.weak) {
      if (kSniGoogleFamily.contains(sni)) googleFamilyPassed = true;
      if (kSniCloudflareFamily.contains(sni)) cloudflareFamilyPassed = true;
    }

    if (bestResult == null) {
      bestResult = candidate;
    } else {
      // Prefer: better tier first, then higher score
      final tierA = candidate.tier.index;
      final tierB = bestResult.tier.index;
      if (tierA < tierB) {
        bestResult = candidate;
      } else if (tierA == tierB && (candidate.score ?? 0) > (bestResult.score ?? 0)) {
        bestResult = candidate;
      }
    }

    // Early exit: already excellent, no need to try more SNIs
    if (bestResult?.tier == IpTier.excellent) break;
  }
  return bestResult ?? dead(ScanPhase.tlsFail);
}

// ── Single SNI pipeline ───────────────────────────────────────────────────────
Future<ScanResult> _scanWithSni(
  String ip,
  String sni,
  int survivalTarget,
  int repeats, {
  required String country,
  required String flag,
  required ScanResult Function(ScanPhase) dead,
}) async {

  // Phase 1-4: TCP → TLS → ServerHello → ApplicationData (up to 5 retries)
  final first = await probeWithRetry(ip, sni: sni, retries: 5);
  if (first == null) return dead(ScanPhase.tlsFail);

  // Capture first timing for adaptive timeout and diagnostic display (fix #6)
  final firstTimings = first.timings;

  // Phase 6: Stability — repeat probes
  // Fix #7: samples.isEmpty dead code removed — we always start with first probe
  final samples   = <double>[first.latencyMs];
  int   failed    = 0;

  // Adaptive server hello timeout for subsequent probes (fix #8)
  final adaptiveMs = adaptiveServerHelloMs(first.latencyMs);

  for (int i = 1; i < repeats; i++) {
    final r = await androidTlsProbe(ip, sni: sni, serverHelloMs: adaptiveMs);
    if (r != null) {
      samples.add(r.latencyMs);
    } else {
      failed++;
    }
    await Future.delayed(const Duration(milliseconds: 200));
  }

  final lossPercent  = ((failed / repeats) * 100).round();
  final reliability  = samples.length / repeats;
  final avg          = samples.reduce((a, b) => a + b) / samples.length;
  final jitter       = calcJitter(samples);

  // Soft stability gate — only reject if ALL probes failed
  // samples.isEmpty is now actually reachable if first probe data lost
  // (shouldn't happen, but defensive coding)
  if (samples.isEmpty) return dead(ScanPhase.stabilityFail);

  // Phase 5+7: Tunnel Survival (pass isCancelled so stop button exits immediately)
  final survival = await tunnelSurvivalTest(
    ip, sni: sni, survivalTargetMs: survivalTarget,
    isCancelled: _currentIsCancelled);

  // Classify phase
  final phase = survival.dpiKilled
      ? ScanPhase.dpiFail
      : survival.survived
          ? ScanPhase.passed
          : ScanPhase.survivalFail;

  // Soft tier classification
  final tier = calcTier(survival.survivalMs, phase);

  // isAlive = anything that got a TLS handshake and survived ≥5s OR just passed
  final isAlive = tier != IpTier.dead && tier != IpTier.weak
      ? true
      : phase == ScanPhase.passed;

  // Bandwidth test — only if at least usable tier
  double? speedKBs;
  if (tier == IpTier.excellent || tier == IpTier.good || tier == IpTier.usable) {
    speedKBs = await measureBandwidthKBs(ip, sni: sni);
  }

  // Score — jitter NOT included (too few samples, fix #5)
  final score = calcScore(
    survived:         survival.survived,
    survivalMs:       survival.survivalMs,
    survivalTargetMs: survivalTarget,
    avgLatencyMs:     avg,
    reliability:      reliability,
  );

  final grade = calcGradeFromScore(score, phase);

  return ScanResult(
    ip:             ip,
    latencyMs:      double.parse(avg.toStringAsFixed(1)),
    jitterMs:       double.parse(jitter.toStringAsFixed(1)),
    isAlive:        isAlive,
    grade:          grade,
    country:        country,
    flag:           flag,
    loss:           lossPercent,
    reliability:    double.parse(reliability.toStringAsFixed(2)),
    score:          score,
    survivalMs:     survival.survivalMs,
    retransmits:    0,
    phase:          phase,
    tier:           tier,
    speedKBs:       speedKBs,
    sniUsed:        sni,
    // Diagnostic breakdown (fix #6)
    tcpLatencyMs:   firstTimings != null
        ? double.parse(firstTimings.tcpMs.toStringAsFixed(1))
        : null,
    tlsHandshakeMs: firstTimings != null
        ? double.parse(firstTimings.tlsMs.toStringAsFixed(1))
        : null,
  );
}

// ─── runScanningEngine ────────────────────────────────────────────────────────
Future<List<ScanResult>> runScanningEngine(
  List<String> ips, {
  ScanMode mode           = ScanMode.normal,
  int concurrency         = 4,
  List<String>? deepSnis,
  void Function(int done, int total, ScanResult result)? onProgress,
  void Function(int liveCount, int totalCount)? onPrefilterDone,
  bool Function()? isCancelled,
}) async {
  final results = <ScanResult>[];
  int   done    = 0;

  // Make cancellation available to tunnelSurvivalTest inside _scanWithSni
  _currentIsCancelled = isCancelled;

  // ── Step 0: Quick TLS pre-filter (fix #2: was TCP-only) ──────────────────
  // Full TLS handshake check — catches TCP-open but TLS-blackhole IPs.
  // Concurrency = 50, timeout = 3s per IP.
  final liveIps      = <String>[];
  final prefilterSem = Semaphore(50);

  await Future.wait(ips.map((ip) async {
    if (isCancelled?.call() == true) return;
    await prefilterSem.acquire();
    try {
      if (isCancelled?.call() == true) return;
      final alive = await quickTlsCheck(ip, timeoutMs: 3000);
      if (alive) liveIps.add(ip);
    } finally {
      prefilterSem.release();
    }
  }));

  onPrefilterDone?.call(liveIps.length, ips.length);
  if (liveIps.isEmpty) return results;

  // ── Step 1: Full scan on live IPs ────────────────────────────────────────
  // Concurrency: normal=8, deep=4 (deep is much heavier per IP)
  final fullConcurrency = mode == ScanMode.deep
      ? min(calcConcurrency(liveIps.length), 4)
      : min(calcConcurrency(liveIps.length), 8);
  final sem       = Semaphore(fullConcurrency);
  final totalLive = liveIps.length;

  await Future.wait(liveIps.map((ip) async {
    if (isCancelled?.call() == true) return;
    await sem.acquire();
    try {
      if (isCancelled?.call() == true) return;
      final r = await scanOneIp(ip, mode: mode, snis: deepSnis);
      results.add(r);
      done++;
      onProgress?.call(done, totalLive, r);
    } finally {
      sem.release();
    }
  }));

  // ── Step 2: Sort by tier → score → latency ───────────────────────────────
  results.sort((a, b) {
    // tier: lower index = better (excellent=0, good=1, usable=2, weak=3, dead=4)
    if (a.tier.index != b.tier.index) return a.tier.index.compareTo(b.tier.index);
    final sa = a.score ?? 0.0;
    final sb = b.score ?? 0.0;
    if (sa != sb) return sb.compareTo(sa);
    return a.latencyMs.compareTo(b.latencyMs);
  });

  return results;
}
