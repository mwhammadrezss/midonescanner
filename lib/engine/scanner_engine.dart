// lib/engine/scanner_engine.dart
// ─── Main orchestrator — uses all engine/model/util modules ─────────────────
import 'dart:async';
import '../models/scan_result.dart';
import '../geo/geoip.dart';
import 'probe_engine.dart';
import 'bandwidth_engine.dart';
import 'grading_engine.dart';
import 'concurrency_engine.dart';
import '../utils/stats_utils.dart';

export '../models/scan_result.dart';
export '../utils/ip_utils.dart';

enum ScanMode { normal, deep }

Future<ScanResult> scanOneIp(
  String ip, {
  int  repeats       = 3,
  bool testBandwidth = false,
}) async {
  final best = await findBestSni(ip);

  if (best == null) {
    final (country, flag) = GeoIPOffline().lookupFull(ip);
    return ScanResult(
      ip:          ip,
      latencyMs:   9999,
      jitterMs:    0,
      isAlive:     false,
      grade:       'F',
      country:     country,
      flag:        flag,
      loss:        100,
      reliability: 0,
      bandwidth:   null,
    );
  }

  // ── Probe loop ────────────────────────────────────────────────────────────
  // samples starts with best.latency so it is always non-empty.
  final samples = <double>[best.latency];
  int failed = 0;

  for (int i = 1; i < repeats; i++) {
    final timeoutMs = dynamicTimeout(best.latency);
    final result    = await tcpProbe(ip, 443, timeoutMs: timeoutMs, sni: best.sni);
    if (result != null) {
      samples.add(result.latency);
    } else {
      failed++;
    }
    await Future.delayed(const Duration(milliseconds: 150));
  }

  final lossPercent = ((failed / repeats) * 100).round();
  final reliability = samples.length / repeats;

  // ── Safe jitter execution ─────────────────────────────────────────────────
  // Guard against empty list before .reduce(); cast explicitly via .toList()
  // to prevent any casting or empty-list runtime crashes.
  final safeSamples = samples.isNotEmpty ? samples.toList() : <double>[0];
  final avg     = safeSamples.reduce((a, b) => a + b) / safeSamples.length;
  final jitter  = calcJitter(safeSamples);
  // ignore: unused_local_variable
  final drift   = calcDrift(safeSamples);  // reserved for throttle detection

  double? bw;
  if (testBandwidth) {
    bw = await bandwidthTest(ip, best.sni);
  }

  final (country, flag) = GeoIPOffline().lookupFull(ip);

  return ScanResult(
    ip:          ip,
    latencyMs:   double.parse(avg.toStringAsFixed(1)),
    jitterMs:    double.parse(jitter.toStringAsFixed(1)),
    isAlive:     true,
    grade:       calcGrade(avg, lossPercent, jitter),
    country:     country,
    flag:        flag,
    loss:        lossPercent,
    reliability: double.parse(reliability.toStringAsFixed(2)),
    bandwidth:   bw,
  );
}

Future<List<ScanResult>> runScanningEngine(
  List<String> ips, {
  ScanMode mode        = ScanMode.normal,
  int      concurrency = 8,
  void Function(int done, int total, ScanResult result)? onProgress,
  bool Function()? isCancelled,
}) async {
  final repeats             = mode == ScanMode.deep ? 5 : 3;
  final results             = <ScanResult>[];
  int   done                = 0;
  final adaptiveConcurrency = calcConcurrency(ips.length);
  final sem                 = Semaphore(adaptiveConcurrency);

  await Future.wait(ips.map((ip) async {
    if (isCancelled?.call() == true) return;
    await sem.acquire();
    try {
      if (isCancelled?.call() == true) return;
      final r = await scanOneIp(ip, repeats: repeats, testBandwidth: true);
      results.add(r);
      done++;
      onProgress?.call(done, ips.length, r);
    } finally {
      sem.release();
    }
  }));

  results.sort((a, b) {
    if (a.isAlive != b.isAlive) return a.isAlive ? -1 : 1;
    return a.latencyMs.compareTo(b.latencyMs);
  });

  return results;
}
