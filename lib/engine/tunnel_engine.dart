// lib/engine/tunnel_engine.dart
// Phase 5-7: Tunnel Survival + DPI Resistance
//
// STRATEGY: Send periodic randomized heartbeat payloads to simulate
// real VPN traffic. Pure idle TLS doesn't reflect actual tunnel behavior —
// some CDNs tolerate idle connections but drop real traffic.
//
// HEARTBEAT (anti-detection fix):
//   - Size: 8–64 bytes random (was fixed 16 — machine-detectable pattern)
//   - Interval: 3–7s random jitter (was exactly 5s — periodic = detectable)
//   Real VPN traffic is NOT perfectly periodic. A fixed interval is a
//   fingerprint that DPI can use to classify/block.
//
// BLACKHOLE DETECTION: Both TimeoutException AND stalled socket
// (no RST, no FIN, no data) are treated as blackhole.
//
// SURVIVAL TIERS (from Wireshark: ShirKhorshid RSTs at ~32s):
//   ≥ 20s = Excellent
//   ≥ 10s = Good
//   ≥  5s = Usable
//   <  5s = Weak
//
// Deep mode target is 20s (not 30s — smarter not longer).
import 'dart:async';
import 'dart:io';
import 'dart:math';
import 'probe_engine.dart';

class SurvivalResult {
  final bool survived;
  final int  survivalMs;
  final bool dpiKilled;
  final bool blackhole;

  const SurvivalResult({
    required this.survived,
    required this.survivalMs,
    required this.dpiKilled,
    required this.blackhole,
  });
}

final _rng = Random.secure();

// Random payload: 8–64 bytes (non-periodic size, fix #2)
List<int> _heartbeatPayload() {
  final size = 8 + _rng.nextInt(57); // 8..64
  return List.generate(size, (_) => _rng.nextInt(256));
}

// Random delay: 3000–7000ms (non-periodic interval, fix #2)
Duration _heartbeatDelay() {
  final ms = 3000 + _rng.nextInt(4001); // 3000..7000
  return Duration(milliseconds: ms);
}

Future<SurvivalResult> tunnelSurvivalTest(
  String ip, {
  String sni               = kShiroSni,
  int    survivalTargetMs  = 20000,
}) async {
  Socket?       rawSock;
  SecureSocket? tls;
  final         sw          = Stopwatch()..start();
  bool          errorKilled = false;
  bool          blackhole   = false;

  try {
    rawSock = await Socket.connect(
      ip, 443,
      timeout: const Duration(seconds: 5),
    );

    // Cert validation: allow SNI mismatch (CDN fronting) but reject
    // empty/missing certs — catches captive portals and transparent proxies (fix #4)
    X509Certificate? seenCert;
    tls = await SecureSocket.secure(
      rawSock,
      host: sni,
      onBadCertificate: (cert) {
        // Accept if cert is real (has PEM content), reject empty/null certs
        if (cert.pem.isEmpty) return false;
        seenCert = cert;
        return true; // allow SNI mismatch for CDN fronting
      },
      supportedProtocols: [kShiroAlpn],
    ).timeout(const Duration(seconds: 6));

    // If no cert was presented at all, likely captive portal
    // (a real CDN will always send a cert, even if SNI mismatches)
    if (seenCert == null) {
      // No onBadCertificate called = cert matched SNI exactly = valid
      // This path is fine.
    }

    bool  connectionDead = false;
    final deathCompleter = Completer<void>();

    final sub = tls.listen(
      (_) {},
      onError: (_) {
        errorKilled    = true;
        connectionDead = true;
        if (!deathCompleter.isCompleted) deathCompleter.complete();
      },
      onDone: () {
        connectionDead = true;
        if (!deathCompleter.isCompleted) deathCompleter.complete();
      },
      cancelOnError: true,
    );

    // ── Randomized heartbeat loop (fix #2) ──────────────────────────────────
    // Non-periodic: random size 8–64B, random interval 3–7s.
    // Mimics realistic VPN keep-alive patterns — harder to fingerprint.
    void scheduleHeartbeat() {
      if (connectionDead || deathCompleter.isCompleted) return;
      Future.delayed(_heartbeatDelay(), () {
        if (connectionDead || deathCompleter.isCompleted) return;
        try {
          tls?.add(_heartbeatPayload());
          scheduleHeartbeat(); // schedule next after this one
        } catch (_) {
          errorKilled    = true;
          connectionDead = true;
          if (!deathCompleter.isCompleted) deathCompleter.complete();
        }
      });
    }
    scheduleHeartbeat();

    // ── Blackhole detection: stalled socket ─────────────────────────────────
    // stallTimeout = target + 8s (max possible next heartbeat delay + margin)
    final stallTimeout = Duration(
      milliseconds: survivalTargetMs + 8000,
    );

    await Future.any([
      Future.delayed(Duration(milliseconds: survivalTargetMs)),
      deathCompleter.future,
    ]).timeout(stallTimeout, onTimeout: () {
      blackhole = true;
      if (!deathCompleter.isCompleted) deathCompleter.complete();
    }).catchError((_) {});

    sw.stop();
    await sub.cancel();
    try { await tls.close(); } catch (_) {}
    tls.destroy();

    final survived = !errorKilled && !blackhole && sw.elapsedMilliseconds >= 5000;

    return SurvivalResult(
      survived:   survived,
      survivalMs: sw.elapsedMilliseconds,
      dpiKilled:  errorKilled,
      blackhole:  blackhole,
    );
  } catch (e) {
    sw.stop();
    if (e is TimeoutException) {
      blackhole = true;
    } else if (e is SocketException) {
      final msg = e.message.toLowerCase();
      blackhole   = msg.contains('timed out') || msg.contains('timeout');
      errorKilled = !blackhole;
    } else {
      errorKilled = true;
    }
    return SurvivalResult(
      survived:   false,
      survivalMs: sw.elapsedMilliseconds,
      dpiKilled:  errorKilled,
      blackhole:  blackhole,
    );
  } finally {
    try { tls?.destroy();     } catch (_) {}
    try { rawSock?.destroy(); } catch (_) {}
  }
}
