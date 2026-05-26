// lib/engine/tunnel_engine.dart
// Phase 5-7: Tunnel Survival + DPI Resistance
//
// STRATEGY: Send periodic tiny encrypted heartbeat payloads to simulate
// real VPN traffic. Pure idle TLS doesn't reflect actual tunnel behavior —
// some CDNs tolerate idle connections but drop real traffic (fix #1).
//
// HEARTBEAT: 16 random bytes every 5 seconds.
// This keeps the connection "alive" like a VPN handshake ping, without
// triggering HTTP-level CDN behavior.
//
// BLACKHOLE DETECTION (fix #11): Both TimeoutException AND stalled socket
// (no RST, no FIN, no data for >heartbeatInterval×2) are treated as blackhole.
//
// SURVIVAL TIERS (from Wireshark: ShirKhorshid RSTs at ~32s):
//   ≥ 20s = Excellent
//   ≥ 10s = Good
//   ≥  5s = Usable
//   <  5s = Weak
//
// Deep mode target reduced to 20s (was 30s) — smarter not longer (fix #10).
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

// 16-byte random payload to keep connection warm (fix #1)
List<int> _heartbeatPayload() {
  final rng = Random.secure();
  return List.generate(16, (_) => rng.nextInt(256));
}

Future<SurvivalResult> tunnelSurvivalTest(
  String ip, {
  String sni               = kShiroSni,
  int    survivalTargetMs  = 20000,  // reduced from 30s (fix #10)
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

    tls = await SecureSocket.secure(
      rawSock,
      host: sni,
      onBadCertificate: (_) => true,
      supportedProtocols: [kShiroAlpn],
    ).timeout(const Duration(seconds: 6));

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

    // ── Heartbeat loop (fix #1): send 16-byte payload every 5 seconds ──────
    // Simulates VPN keep-alive traffic. If the CDN drops real traffic,
    // the socket will error here — caught by onError above.
    const heartbeatInterval = Duration(seconds: 5);
    Timer.periodic(heartbeatInterval, (timer) {
      if (connectionDead || deathCompleter.isCompleted) {
        timer.cancel();
        return;
      }
      try {
        tls?.add(_heartbeatPayload());
      } catch (_) {
        // Write failure = connection dead
        errorKilled = true;
        connectionDead = true;
        timer.cancel();
        if (!deathCompleter.isCompleted) deathCompleter.complete();
      }
    });

    // ── Blackhole detection (fix #11): stalled socket timeout ───────────────
    // If connection doesn't die (no RST/FIN) but also never responds, it's a
    // blackhole. We detect this via the survivalTarget timeout itself — if we
    // hit the target without error, we survived. If we get no signal and no
    // error within 2× heartbeat interval past target, treat as blackhole.
    final stallTimeout = Duration(
      milliseconds: survivalTargetMs + heartbeatInterval.inMilliseconds * 2,
    );

    await Future.any([
      Future.delayed(Duration(milliseconds: survivalTargetMs)),
      deathCompleter.future,
    ]).timeout(stallTimeout, onTimeout: () {
      // No RST, no FIN, no response = silent blackhole
      blackhole = true;
      if (!deathCompleter.isCompleted) deathCompleter.complete();
    }).catchError((_) {});

    sw.stop();
    await sub.cancel();
    try { await tls.close(); } catch (_) {}
    tls.destroy();

    // Survived = no RST error AND lasted at least 5s
    // Blackhole = stalled: treat as "not survived" but different cause
    final survived = !errorKilled && !blackhole && sw.elapsedMilliseconds >= 5000;

    return SurvivalResult(
      survived:   survived,
      survivalMs: sw.elapsedMilliseconds,
      dpiKilled:  errorKilled,
      blackhole:  blackhole,
    );
  } catch (e) {
    sw.stop();
    // TimeoutException = classic blackhole (fix #11: was only timeout)
    // SocketException with "connection refused" or "reset" = DPI killed
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
