// ================================================================
// MidOne DNS Scanner — Stage 1: Latency
// ================================================================
//
// Goal:   Fast pre-filter. Discard clearly slow / dead servers.
// Method: Send [latencySamples] A-queries for a stable domain.
//         Use average latency (not min) to catch servers that are
//         "fast sometimes but unreliable".
// Output: Top [stage1KeepTop] servers sorted by avgLatencyMs.
// ================================================================

import '../dns_resolver.dart';
import '../models.dart';

class Stage1Latency {
  static const String _probeDomain = 'example.com';

  static Future<List<DNSServer>> run(
    List<DNSServer> candidates,
    ScanConfig config, {
    void Function(ScanProgress)? onProgress,
  }) async {
    int tested = 0;

    final results = await concurrentMap<DNSServer, DNSServer>(
      candidates,
      (server) async {
        final latencies = <double>[];

        // Take [latencySamples] measurements
        for (int i = 0; i < config.latencySamples; i++) {
          final result = await DnsResolver.query(
            server.ip,
            _probeDomain,
            timeout: config.queryTimeout,
          );
          if (result.success && result.latencyMs.isFinite) {
            latencies.add(result.latencyMs);
          }
        }

        server.currentStage = ScanStage.stage1Latency;

        if (latencies.isEmpty) {
          // Completely unresponsive
          server.eliminated = true;
          server.eliminationReason = EliminationReason.highLatency;
          server.currentStage = ScanStage.eliminated;
        } else {
          final avg = latencies.reduce((a, b) => a + b) / latencies.length;
          server.avgLatencyMs = avg;
          server.minLatencyMs = latencies.reduce((a, b) => a < b ? a : b);
        }

        tested++;
        onProgress?.call(ScanProgress(
          stage: ScanStage.stage1Latency,
          tested: tested,
          total: candidates.length,
          survivors: -1, // calculated after sort
          message: 'Latency: tested $tested/${candidates.length}',
          percentage: tested / candidates.length * 0.20, // Stage 1 = 0–20%
        ));

        return server;
      },
      concurrency: config.concurrencyStage1,
    );

    // Remove completely dead servers
    final responsive = results
        .where((s) => !s.eliminated && s.avgLatencyMs != null)
        .toList();

    // Sort ascending by average latency
    responsive.sort((a, b) => a.avgLatencyMs!.compareTo(b.avgLatencyMs!));

    // Keep top N
    final survivors = responsive.take(config.stage1KeepTop).toList();

    // Assign latency ranks (1 = best)
    for (int i = 0; i < survivors.length; i++) {
      survivors[i].latencyRank = i + 1;
    }

    // FIX #1: guard against empty survivors list (all servers dead / no network).
    // Previously survivors.first would throw StateError here.
    final summaryTail = survivors.isEmpty
        ? 'no responsive servers found'
        : '(best: ${survivors.first.avgLatencyMs!.toStringAsFixed(0)} ms)';

    onProgress?.call(ScanProgress(
      stage: ScanStage.stage1Latency,
      tested: candidates.length,
      total: candidates.length,
      survivors: survivors.length,
      message:
          'Stage 1 complete: ${survivors.length} / ${candidates.length} passed '
          '$summaryTail',
      percentage: 0.20,
    ));

    return survivors;
  }
}
