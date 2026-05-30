// ================================================================
// MidOne DNS Scanner — Stage 3: Burst + Jitter + Packet Loss
// ================================================================
//
// Goal:   Stress-test DNS under rapid-fire load (realistic mobile use).
//         A fast-looking server can collapse under burst.
//
// Method:
//   Send [burstCount] queries concurrently to the same server.
//   Measure:
//     • Burst success rate   (answered / sent)
//     • Jitter               (std-dev of latencies)
//     • Packet loss rate     (1 - success rate over [packetLossProbes] probes)
//
//   Also check IPv6 support (AAAA query for a known dual-stack domain).
//
// Output: Top [stage3KeepTop] servers by composite burst score.
// ================================================================

import 'dart:math';

import '../dns_resolver.dart';
import '../models.dart';

class Stage3BurstJitter {
  static const _burstDomain   = 'google.com';
  static const _ipv6Domain    = 'ipv6.google.com'; // Always resolves AAAA only

  static Future<List<DNSServer>> run(
    List<DNSServer> candidates,
    ScanConfig config, {
    void Function(ScanProgress)? onProgress,
  }) async {
    int tested = 0;

    final results = await concurrentMap<DNSServer, DNSServer>(
      candidates,
      (server) async {
        server.currentStage = ScanStage.stage3BurstJitter;

        // ── Burst test ──────────────────────────────────────
        final burstResults = await DnsResolver.queryBurst(
          server.ip,
          _burstDomain,
          count: config.burstCount,
          timeout: config.queryTimeout,
        );

        final successful = burstResults.where((r) => r.success).toList();
        final latencies  = successful.map((r) => r.latencyMs).toList();

        server.burstSuccessRate =
            burstResults.isEmpty ? 0.0 : successful.length / burstResults.length;
        server.jitterMs = latencies.length >= 2 ? stdDev(latencies) : 0.0;

        // ── Packet loss (additional probes, spaced slightly) ────
        final lossResults = await _packetLossProbes(
          server.ip,
          config,
        );
        server.packetLossRate = lossResults;

        // ── IPv6 support ─────────────────────────────────────
        final ipv6result = await DnsResolver.query(
          server.ip,
          _ipv6Domain,
          qtype: DnsType.aaaa,
          timeout: config.queryTimeout,
        );
        server.supportsIPv6 = ipv6result.success && ipv6result.aaaaRecords.isNotEmpty;

        tested++;
        onProgress?.call(ScanProgress(
          stage: ScanStage.stage3BurstJitter,
          tested: tested,
          total: candidates.length,
          survivors: -1,
          message: 'Burst test: $tested/${candidates.length}',
          percentage: 0.40 + tested / candidates.length * 0.15,
        ));

        return server;
      },
      concurrency: config.concurrencyStage3,
    );

    // Sort by burst composite score (lower jitter + higher success)
    results.sort((a, b) => _burstScore(b, config).compareTo(_burstScore(a, config)));

    final survivors = results.take(config.stage3KeepTop).toList();

    onProgress?.call(ScanProgress(
      stage: ScanStage.stage3BurstJitter,
      tested: candidates.length,
      total: candidates.length,
      survivors: survivors.length,
      message:
          'Stage 3 complete: ${survivors.length} / ${candidates.length} pass burst test',
      percentage: 0.55,
    ));

    return survivors;
  }

  // ── Packet loss probes ───────────────────────────────────────

  /// Send a series of probes and return packet loss rate (0.0–1.0).
  static Future<double> _packetLossProbes(
    String serverIp,
    ScanConfig config,
  ) async {
    // Stagger probes slightly to simulate realistic conditions
    int lost = 0;
    for (int i = 0; i < config.packetLossProbes; i++) {
      final r = await DnsResolver.query(
        serverIp,
        'example.com',
        timeout: config.queryTimeout,
      );
      if (!r.success) lost++;

      // Small stagger between probes
      await Future.delayed(const Duration(milliseconds: 50));
    }
    return lost / config.packetLossProbes;
  }

  // ── Burst scoring ────────────────────────────────────────────

  static double _burstScore(DNSServer s, ScanConfig config) {
    final successRate  = s.burstSuccessRate ?? 0.0;
    final jitterPenalty = _normalizeJitter(s.jitterMs ?? 999);
    final lossRate     = s.packetLossRate ?? 1.0;

    // Higher = better
    return successRate * 0.5 +
        (1.0 - jitterPenalty) * 0.3 +
        (1.0 - lossRate) * 0.2;
  }

  /// Normalize jitter: 0ms→0.0 (perfect), 100+ms→1.0 (terrible)
  static double _normalizeJitter(double jitterMs) =>
      clamp(jitterMs / 100.0, 0.0, 1.0);
}
