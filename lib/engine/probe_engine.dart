// lib/engine/probe_engine.dart
// Android-like TLS fingerprint probe
import 'dart:async';
import 'dart:io';
import '../models/probe_result.dart';

const kShiroSni  = 'www.google.com';
const kShiroAlpn = 'http/1.1';

Future<({double latencyMs, int retransmits})?> androidTlsProbe(
  String ip, {
  int timeoutMs     = 5000,
  int serverHelloMs = 6000,
}) async {
  Socket?       rawSock;
  SecureSocket? tls;
  try {
    final sw = Stopwatch()..start();

    rawSock = await Socket.connect(
      ip, 443,
      timeout: Duration(milliseconds: timeoutMs),
    );

    tls = await SecureSocket.secure(
      rawSock,
      host: kShiroSni,
      onBadCertificate: (_) => true,
      supportedProtocols: [kShiroAlpn],
    ).timeout(Duration(milliseconds: serverHelloMs));

    sw.stop();

    // Drain a tiny bit to confirm ApplicationData (Phase 4)
    final completer = Completer<void>();
    StreamSubscription? sub;
    sub = tls.listen(
      (_) { if (!completer.isCompleted) completer.complete(); },
      onError: (_) { if (!completer.isCompleted) completer.complete(); },
      onDone:  () { if (!completer.isCompleted) completer.complete(); },
    );
    await completer.future
        .timeout(const Duration(seconds: 2))
        .catchError((_) {});
    await sub.cancel();

    try { await tls.close(); } catch (_) {}
    tls.destroy();

    return (latencyMs: sw.elapsedMicroseconds / 1000.0, retransmits: 0);
  } catch (_) {
    return null;
  } finally {
    try { tls?.destroy();     } catch (_) {}
    try { rawSock?.destroy(); } catch (_) {}
  }
}

Future<({double latencyMs, int retransmits})?> probeWithRetry(
  String ip, {
  int retries = 3,
}) async {
  for (int i = 0; i < retries; i++) {
    final r = await androidTlsProbe(ip);
    if (r != null) return r;
    if (i < retries - 1) {
      await Future.delayed(const Duration(milliseconds: 300));
    }
  }
  return null;
}

// Kept for architectural compatibility
class ProbeResult {
  final bool   success;
  final double latency;
  final int    statusCode;
  final String server;
  final String protocol;
  final bool   tlsValid;
  final int    bytesReceived;
  final bool   frontingPossible;

  const ProbeResult({
    required this.success,
    required this.latency,
    required this.statusCode,
    required this.server,
    required this.protocol,
    required this.tlsValid,
    required this.bytesReceived,
    required this.frontingPossible,
  });
}
