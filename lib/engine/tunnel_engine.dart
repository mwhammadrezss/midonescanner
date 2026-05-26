// lib/engine/tunnel_engine.dart
// Phase 5-7: Tunnel Survival + DPI Resistance
//
// STRATEGY: Hold the TLS connection open silently and measure how long
// the CDN edge keeps it alive before sending RST/FIN.
//
// WHY NO HTTP KEEPALIVE:
// Sending HTTP requests (OPTIONS etc.) causes the CDN to close the connection
// gracefully after responding — this is normal HTTP behavior, NOT a scan fail.
// ShirKhorshid sends its own VPN protocol data through the tunnel, not HTTP.
// The correct test is: does the raw TLS connection stay alive long enough?
//
// From Wireshark: ShirKhorshid's CDN connection RSTs at ~32 seconds.
// A connection surviving 10+ seconds = usable for ShirKhorshid.
// A connection surviving 20-30 seconds = ideal (full score).
import 'dart:async';
import 'dart:io';
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

Future<SurvivalResult> tunnelSurvivalTest(
  String ip, {
  String sni               = kShiroSni,
  int    survivalTargetMs  = 25000,
}) async {
  Socket?       rawSock;
  SecureSocket? tls;
  final         sw        = Stopwatch()..start();
  bool          dpiKilled = false;
  bool          blackhole = false;

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

    // Hold the connection open silently.
    // onError = RST or network error (bad IP or ISP killed it)
    // onDone  = graceful FIN (CDN idle-timeout — normal, not a kill)
    // We distinguish: error = dpiKilled, done = natural close (measure time)
    bool  errorKilled    = false;
    bool  connectionDead = false;
    final deathCompleter = Completer<void>();

    final sub = tls.listen(
      (_) {}, // drain any data the CDN might send
      onError: (_) {
        errorKilled  = true;
        connectionDead = true;
        if (!deathCompleter.isCompleted) deathCompleter.complete();
      },
      onDone: () {
        // Graceful close — CDN naturally ended the connection.
        // This is NOT a kill; it just means the connection ended normally.
        connectionDead = true;
        if (!deathCompleter.isCompleted) deathCompleter.complete();
      },
      cancelOnError: true,
    );

    // Wait until either: target time reached, or connection dies
    await Future.any([
      Future.delayed(Duration(milliseconds: survivalTargetMs)),
      deathCompleter.future,
    ]);

    sw.stop();
    await sub.cancel();
    try { await tls.close(); } catch (_) {}
    tls.destroy();

    dpiKilled = errorKilled;

    // Survived = no error AND stayed alive for at least half the target
    // (10s for normal mode, 15s for deep mode)
    final survived = !errorKilled &&
        sw.elapsedMilliseconds >= survivalTargetMs ~/ 2;

    return SurvivalResult(
      survived:   survived,
      survivalMs: sw.elapsedMilliseconds,
      dpiKilled:  dpiKilled,
      blackhole:  blackhole,
    );
  } catch (e) {
    sw.stop();
    blackhole = e is TimeoutException;
    dpiKilled = !blackhole;
    return SurvivalResult(
      survived:   false,
      survivalMs: sw.elapsedMilliseconds,
      dpiKilled:  dpiKilled,
      blackhole:  blackhole,
    );
  } finally {
    try { tls?.destroy();     } catch (_) {}
    try { rawSock?.destroy(); } catch (_) {}
  }
}
