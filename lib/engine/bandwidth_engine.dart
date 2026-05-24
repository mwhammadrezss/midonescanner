// lib/engine/bandwidth_engine.dart
import 'dart:io';
import 'tls_engine.dart';

int dynamicTimeout(double previousLatency) {
  if (previousLatency < 100) return 2000;
  if (previousLatency < 300) return 4000;
  return 6000;
}

/// Quick Mode  → 100 KB
/// Stress Mode → 5 MB / 15 s
Future<double?> bandwidthTest(
  String ip,
  String sni, {
  bool stressMode = false,
}) async {
  final int targetBytes = stressMode ? 5 * 1024 * 1024 : 102400;
  final int maxMs       = stressMode ? 15000 : 4000;
  final path = sni == 'speed.cloudflare.com'
      ? '/__down?bytes=$targetBytes'
      : '/';

  Socket? sock;
  try {
    sock = await Socket.connect(ip, 443,
        timeout: const Duration(seconds: 4));

    final secSock = await SecureSocket.secure(
      sock,
      host: sni,
      onBadCertificate: (cert) => validateCert(cert),
    );

    secSock.write(
      'GET $path HTTP/1.1\r\n'
      'Host: $sni\r\n'
      'User-Agent: MidONe/1.0\r\n'
      'Connection: close\r\n\r\n',
    );

    int total = 0;
    final sw = Stopwatch()..start();

    await secSock
        .listen((d) {
          total += d.length;
          if (total >= targetBytes ||
              sw.elapsed.inMilliseconds >= maxMs) {
            throw 'done';
          }
        })
        .asFuture()
        .timeout(Duration(milliseconds: maxMs + 1000))
        .catchError((_) {});

    sw.stop();

    await secSock.flush();
    await secSock.close();
    secSock.destroy();

    if (total > 500 && sw.elapsedMilliseconds > 0) {
      final mbps = (total * 8) / (sw.elapsedMilliseconds * 1000);
      return double.parse(mbps.toStringAsFixed(2));
    }
    return null;
  } catch (_) {
    return null;
  } finally {
    sock?.destroy();
  }
}
