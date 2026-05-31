// ================================================================
// MidOne DNS Scanner — Main Orchestrator
// ================================================================
//
// Usage:
//
//   final scanner = DNSScanner(config: ScanConfig());
//
//   await for (final progress in scanner.scan(serverIps)) {
//     print(progress.message);
//     if (progress.stage == ScanStage.complete) {
//       final results = scanner.results;  // final ranked list
//     }
//   }
//
// ================================================================

import 'dart:async';

import 'models.dart';
import 'dns_servers.dart';
import 'source_of_truth.dart';
import 'stages/stage1_latency.dart';
import 'stages/stage2_nxdomain_hijack.dart';
import 'stages/stage3_burst_jitter.dart';
import 'stages/stage4_freedom.dart';
import 'stages/stage5_doh_final.dart';

export 'models.dart';
export 'source_of_truth.dart';

class DNSScanner {
  final ScanConfig config;

  List<DNSServer> _results = [];
  List<DNSServer> get results => List.unmodifiable(_results);

  DNSScanner({ScanConfig? config}) : config = config ?? const ScanConfig();

  // ── Main entry point ─────────────────────────────────────────

  /// Scan a list of DNS server IPs.
  /// Yields [ScanProgress] updates throughout in real time.
  /// After the final yield, read [results] for the ranked list.
  Stream<ScanProgress> scan(List<String> serverIps) async* {
    final sot = SourceOfTruth(
      providers: config.dohProviders,
      timeout: config.dohTimeout,
    );

    // Test which SoT providers are available on this network
    yield ScanProgress(
      stage: ScanStage.pending,
      tested: 0,
      total: serverIps.length,
      survivors: serverIps.length,
      message: 'Checking source-of-truth availability…',
      percentage: 0.0,
    );

    final sotStatus = await sot.testProviders();
    final availableProviders = sotStatus.entries
        .where((e) => e.value)
        .map((e) => e.key)
        .toList();

    // FIX #7: rebuild sot with only reachable providers
    final effectiveSot = availableProviders.isNotEmpty
        ? SourceOfTruth(
            providers: availableProviders,
            timeout: config.dohTimeout,
          )
        : sot;

    if (availableProviders.isEmpty) {
      yield ScanProgress(
        stage: ScanStage.pending,
        tested: 0,
        total: serverIps.length,
        survivors: serverIps.length,
        message: '⚠️ No DoH providers reachable. Freedom scoring will be limited.',
        percentage: 0.01,
      );
    }

    // Build server list
    var servers = serverIps
        .map((ip) => DNSServer(ip: ip))
        .toList();

    yield ScanProgress(
      stage: ScanStage.pending,
      tested: 0,
      total: servers.length,
      survivors: servers.length,
      message: 'Starting scan of ${servers.length} DNS servers…',
      percentage: 0.02,
    );

    // ── Stage 1: Latency ──────────────────────────────────────
    // FIX (real-time): Use a StreamController to forward each onProgress
    // event immediately as it arrives — no buffering, no waiting for stage end.
    {
      final ctrl = StreamController<ScanProgress>();
      final scanFuture = Stage1Latency.run(
        servers,
        config,
        onProgress: ctrl.add,
      ).then((result) {
        ctrl.close();
        return result;
      }).catchError((Object e) {
        ctrl.addError(e);
        ctrl.close();
        return <DNSServer>[];
      });

      await for (final p in ctrl.stream) {
        yield p;
      }
      servers = await scanFuture;
    }

    yield ScanProgress(
      stage: ScanStage.stage1Latency,
      tested: serverIps.length,
      total: serverIps.length,
      survivors: servers.length,
      message:
          'Stage 1 ✓ — ${servers.length} fast servers found '
          '(from ${serverIps.length})',
      percentage: 0.20,
    );

    if (servers.isEmpty) {
      yield ScanProgress(
        stage: ScanStage.complete,
        tested: serverIps.length,
        total: serverIps.length,
        survivors: 0,
        message: '❌ No responsive DNS servers found. '
            'Check your network connection and try again.',
        percentage: 1.0,
      );
      return;
    }

    // ── Stage 2A: NXDOMAIN ────────────────────────────────────
    // FIX: real-time progress forwarding via StreamController
    {
      final ctrl = StreamController<ScanProgress>();
      final scanFuture = Stage2aNxdomain.run(
        servers,
        config,
        onProgress: ctrl.add,
      ).then((result) {
        ctrl.close();
        return result;
      }).catchError((Object e) {
        ctrl.addError(e);
        ctrl.close();
        return <DNSServer>[];
      });

      await for (final p in ctrl.stream) {
        yield p;
      }
      servers = await scanFuture;
    }

    yield ScanProgress(
      stage: ScanStage.stage2aNxdomain,
      tested: servers.length,
      total: serverIps.length,
      survivors: servers.length,
      message: 'Stage 2A ✓ — ${servers.length} servers pass NXDOMAIN check',
      percentage: 0.30,
    );

    if (servers.isEmpty) {
      yield ScanProgress(
        stage: ScanStage.complete,
        tested: serverIps.length,
        total: serverIps.length,
        survivors: 0,
        message: '❌ All servers failed NXDOMAIN integrity check '
            '(possible DNS hijacking on this network).',
        percentage: 1.0,
      );
      return;
    }

    // ── Stage 2B: Hijack ──────────────────────────────────────
    // FIX: real-time progress forwarding via StreamController
    {
      final ctrl = StreamController<ScanProgress>();
      final scanFuture = Stage2bHijack.run(
        servers,
        config,
        effectiveSot,
        onProgress: ctrl.add,
      ).then((result) {
        ctrl.close();
        return result;
      }).catchError((Object e) {
        ctrl.addError(e);
        ctrl.close();
        return <DNSServer>[];
      });

      await for (final p in ctrl.stream) {
        yield p;
      }
      servers = await scanFuture;
    }

    yield ScanProgress(
      stage: ScanStage.stage2bHijack,
      tested: servers.length,
      total: serverIps.length,
      survivors: servers.length,
      message: 'Stage 2B ✓ — ${servers.length} servers pass hijack check',
      percentage: 0.40,
    );

    if (servers.isEmpty) {
      yield ScanProgress(
        stage: ScanStage.complete,
        tested: serverIps.length,
        total: serverIps.length,
        survivors: 0,
        message: '❌ All servers detected as hijacking DNS responses.',
        percentage: 1.0,
      );
      return;
    }

    // ── Stage 3: Burst + Jitter + Packet Loss ─────────────────
    // FIX: real-time progress forwarding via StreamController
    {
      final ctrl = StreamController<ScanProgress>();
      final scanFuture = Stage3BurstJitter.run(
        servers,
        config,
        onProgress: ctrl.add,
      ).then((result) {
        ctrl.close();
        return result;
      }).catchError((Object e) {
        ctrl.addError(e);
        ctrl.close();
        return <DNSServer>[];
      });

      await for (final p in ctrl.stream) {
        yield p;
      }
      servers = await scanFuture;
    }

    yield ScanProgress(
      stage: ScanStage.stage3BurstJitter,
      tested: servers.length,
      total: serverIps.length,
      survivors: servers.length,
      message: 'Stage 3 ✓ — ${servers.length} stable servers (burst passed)',
      percentage: 0.55,
    );

    // Stage 3 sorts but never eliminates — no empty-list check needed.

    // ── Stage 4: Freedom Score ────────────────────────────────
    // FIX: real-time progress forwarding via StreamController
    {
      final ctrl = StreamController<ScanProgress>();
      final scanFuture = Stage4Freedom.run(
        servers,
        config,
        effectiveSot,
        onProgress: ctrl.add,
      ).then((result) {
        ctrl.close();
        return result;
      }).catchError((Object e) {
        ctrl.addError(e);
        ctrl.close();
        return <DNSServer>[];
      });

      await for (final p in ctrl.stream) {
        yield p;
      }
      servers = await scanFuture;
    }

    yield ScanProgress(
      stage: ScanStage.stage4Freedom,
      tested: servers.length,
      total: serverIps.length,
      survivors: servers.length,
      message: 'Stage 4 ✓ — ${servers.length} free DNS servers identified',
      percentage: 0.80,
    );

    // Stage 4 guarantees at least 1 server via fallback logic.

    // ── Stage 5: DoH + Final Ranking ─────────────────────────
    // FIX: real-time progress forwarding via StreamController
    {
      final ctrl = StreamController<ScanProgress>();
      final scanFuture = Stage5DoHFinal.run(
        servers,
        config,
        onProgress: ctrl.add,
      ).then((result) {
        ctrl.close();
        return result;
      }).catchError((Object e) {
        ctrl.addError(e);
        ctrl.close();
        return <DNSServer>[];
      });

      await for (final p in ctrl.stream) {
        yield p;
      }
      servers = await scanFuture;
    }

    _results = servers;

    yield ScanProgress(
      stage: ScanStage.complete,
      tested: serverIps.length,
      total: serverIps.length,
      survivors: servers.length,
      message: _buildSummary(servers),
      percentage: 1.0,
    );
  }

  // ── Helpers ──────────────────────────────────────────────────

  String _buildSummary(List<DNSServer> top) {
    final sb = StringBuffer('🏆 Scan complete! Top ${top.length} DNS:\n');
    for (final s in top) {
      sb.write(
        '  #${s.finalRank}: ${s.ip}'
        ' | score=${s.finalScore?.toStringAsFixed(1)}'
        ' | freedom=${((s.freedomScore ?? 0) * 100).toStringAsFixed(0)}%'
        ' | latency=${s.avgLatencyMs?.toStringAsFixed(0)}ms'
        '${s.supportsDoH == true ? " | DoH✓" : ""}'
        '\n',
      );
    }
    return sb.toString();
  }
}

// ================================================================
// Default DNS server list
// ================================================================
// A curated starting list of public DNS servers known to work
// reasonably well in Iran and the Middle East region.

// Backward compatible alias — full list is in dns_servers.dart
// kAllDnsServers contains 2500+ servers (Iranian + international)
const List<String> kDefaultDnsServers = kAllDnsServers;
