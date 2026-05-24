// lib/engine/probe_engine.dart
import 'dart:io';
import '../models/provider_type.dart';
import '../models/probe_result.dart';
import 'tls_engine.dart';
import 'sni_engine.dart';
import '../utils/validators.dart';

Future<ProbeResult?> tcpProbe(
  String ip,
  int    port, {
  int    timeoutMs = 4000,
  String sni       = 'speed.cloudflare.com',
}) async {
  Socket? sock;
  try {
    final sw = Stopwatch()..start();

    sock = await Socket.connect(
      ip, port,
      timeout: Duration(milliseconds: timeoutMs),
    );

    final secSock = await SecureSocket.secure(
      sock,
      host: sni,
      onBadCertificate: (cert) => validateCert(cert),
    );

    secSock.write(
      'GET / HTTP/1.1\r\n'
      'Host: $sni\r\n'
      'User-Agent: MidONe/1.0\r\n'
      'Connection: close\r\n\r\n',
    );

    final buf = StringBuffer();
    await secSock
        .listen((d) {
          buf.write(String.fromCharCodes(d));
          if (buf.length > 256) throw 'done';
        })
        .asFuture()
        .timeout(const Duration(milliseconds: 3000))
        .catchError((_) {});

    sw.stop();

    await secSock.flush();
    await secSock.close();
    secSock.destroy();

    final resp = buf.toString();
    if (!isValidHttpResponse(resp)) return null;

    int statusCode = 0;
    final statusMatch = RegExp(r'HTTP/[\d.]+ (\d+)').firstMatch(resp);
    if (statusMatch != null) {
      statusCode = int.tryParse(statusMatch.group(1) ?? '0') ?? 0;
    }

    String server = '';
    final serverMatch = RegExp(r'[Ss]erver: ([^\r\n]+)').firstMatch(resp);
    if (serverMatch != null) {
      server = serverMatch.group(1)?.trim() ?? '';
    }

    final provider = detectProvider(server);

    return ProbeResult(
      success:          true,
      latency:          sw.elapsedMicroseconds / 1000.0,
      statusCode:       statusCode,
      server:           server,
      protocol:         resp.startsWith('HTTP/2') ? 'HTTP/2' : 'HTTP/1.1',
      tlsValid:         true,
      bytesReceived:    resp.length,
      frontingPossible: provider != ProviderType.unknown,
    );
  } catch (_) {
    return null;
  } finally {
    sock?.destroy();
  }
}

Future<({String sni, double latency})?> findBestSni(String ip) async {
  final allSnis = [
    ...providerSnis[ProviderType.cloudflare]!,
    ...providerSnis[ProviderType.akamai]!,
    ...providerSnis[ProviderType.fastly]!,
  ];

  for (final sni in allSnis) {
    final result = await tcpProbe(ip, 443, timeoutMs: 4000, sni: sni);
    if (result != null) return (sni: sni, latency: result.latency);
  }
  return null;
}
