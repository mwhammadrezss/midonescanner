// lib/engine/bandwidth_engine.dart
import 'dart:async';
import 'dart:io';
import 'tls_engine.dart';

int dynamicTimeout(double previousLatency) {
  if (previousLatency < 100) return 2000;
  if (previousLatency < 300) return 4000;
  return 6000;
}

/// Quick Mode  → 512 KB max / 3 s
/// Stress Mode → 5 MB / 15 s
Future<double?> bandwidthTest(
  String ip,
  String sni, {
  bool stressMode = false,
}) async {
  // ── Adaptive data budget ──────────────────────────────────────────────────
  // Quick: 512 KB cap is more than enough to calculate peak Mbps for fast IPs.
  // Stress: 5 MB / 15 s for deep mode.
  final int maxBytes = stressMode ? 5 * 1024 * 1024 : 524288;
  final int maxMs    = stressMode ? 15000 : 3000;

  final String path = sni == 'speed.cloudflare.com'
      ? '/__down?bytes=$maxBytes'
      : '/';

  Socket?             sock;
  SecureSocket?       secSock;
  StreamSubscription? subscription;

  try {
    sock = await Socket.connect(ip, 443,
        timeout: const Duration(seconds: 4));

    secSock = await SecureSocket.secure(
      sock,
      host: sni,
      onBadCertificate: (cert) => validateCert(cert),
    );

    secSock.write(
      'GET \$path HTTP/1.1\r\n'
      'Host: \$sni\r\n'
      'User-Agent: MidONe/1.0\r\n'
      'Connection: close\r\n\r\n',
    );

    int    total = 0;
    final  sw    = Stopwatch()..start();
    final  completer = Completer<void>();

    // ── Bulletproof stream cleanup ────────────────────────────────────────
    // cancel() subscription first, then close/destroy to prevent
    // "Bad File Descriptor" on Android.
    subscription = secSock.listen(
      (chunk) {
        total += chunk.length;
        // ── Adaptive cutoff: max bytes OR max time ──────────────────────
        if (total >= maxBytes || sw.elapsed.inMilliseconds >= maxMs) {
          subscription?.cancel();
          if (!completer.isCompleted) completer.complete();
        }
      },
      onError: (e) {
        if (!completer.isCompleted) completer.completeError(e);
      },
      onDone: () {
        if (!completer.isCompleted) completer.complete();
      },
      cancelOnError: true,
    );

    await completer.future
        .timeout(Duration(milliseconds: maxMs + 1000))
        .catchError((_) {});

    sw.stop();

    // ── Strict cleanup order: cancel → close → destroy ────────────────────
    await subscription.cancel();
    await secSock.flush();
    await secSock.close();
    secSock.destroy();

    // ── Sane Mbps calculation ─────────────────────────────────────────────
    // Even if a slow IP only downloaded 50 KB in 3 s, we still calculate
    // its exact Mbps (never return null for alive IPs).
    if (total > 1024 && sw.elapsedMilliseconds > 0) {
      final mbps = (total * 8) / (sw.elapsedMilliseconds * 1000);
      return double.parse(mbps.toStringAsFixed(2));
    }
    return null;

  } catch (_) {
    return null;
  } finally {
    // ── Final safety net ─────────────────────────────────────────────────
    try { await subscription?.cancel(); } catch (_) {}
    try { await secSock?.close();       } catch (_) {}
    try { secSock?.destroy();           } catch (_) {}
    sock?.destroy();
  }
}
