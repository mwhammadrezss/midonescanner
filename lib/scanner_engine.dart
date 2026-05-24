import 'dart:async';
import 'dart:io';
import 'dart:math';

import 'geoip.dart';

// ─── CDN Map ───────────────────────────────────────────────────────────────

class CdnInfo {
  final List<String> headers;
  final List<String> server;
  final List<String> snis;
  final String endpoint;
  const CdnInfo({
    required this.headers,
    required this.server,
    required this.snis,
    required this.endpoint,
  });
}

const Map<String, CdnInfo> cdnMap = {
  'Cloudflare': CdnInfo(
    headers: ['cf-ray', 'cf-cache-status', 'cf-request-id'],
    server: ['cloudflare'],
    snis: ['speed.cloudflare.com', 'cloudflare.com'],
    endpoint: '/__down?bytes=8000000',
  ),
  'Akamai': CdnInfo(
    headers: ['x-check-cacheable', 'x-serial', 'x-true-cache-key', 'akamai-origin-hop'],
    server: ['akamaighost', 'akamai'],
    snis: [
      'a248.e.akamai.net', 'a77.net.akamai.net', 'a104.net.akamai.net',
      'a184.net.akamai.net', 'ds-aksb.akamaized.net', 'ak.net.akamaized.net',
    ],
    endpoint: '/',
  ),
  'Google': CdnInfo(
    headers: ['x-goog-generation', 'x-guploader-uploadid', 'x-goog-hash'],
    server: ['gws', 'google frontend', 'esf', 'sffe'],
    snis: ['fonts.googleapis.com', 'google.com', 'www.google.com'],
    endpoint: '/',
  ),
  'Amazon': CdnInfo(
    headers: ['x-amz-cf-id', 'x-amz-cf-pop', 'x-amz-request-id'],
    server: ['amazons3', 'cloudfront'],
    snis: ['d1.cloudfront.net', 'aws.amazon.com'],
    endpoint: '/',
  ),
  'Azure': CdnInfo(
    headers: ['x-azure-ref', 'x-msedge-ref', 'x-ec-custom-error'],
    server: ['microsoft-azure', 'ecd'],
    snis: ['ajax.aspnetcdn.com'],
    endpoint: '/',
  ),
  'Fastly': CdnInfo(
    headers: ['x-served-by', 'x-fastly-request-id', 'x-cache-hits'],
    server: ['varnish'],
    snis: ['global.fastly.net'],
    endpoint: '/',
  ),
  'Iranian': CdnInfo(
    headers: [],
    server: [],
    snis: ['aparat.com', 'snapp.ir', 'digikala.com', 'telewebion.com', 'varzesh3.com'],
    endpoint: '/',
  ),
};

List<String> get allSnis {
  final list = <String>[];
  for (final info in cdnMap.values) {
    for (final s in info.snis) {
      if (!list.contains(s)) list.add(s);
    }
  }
  return list;
}

// ─── Config ────────────────────────────────────────────────────────────────

class ScanConfig {
  final int threads;
  final Duration connectTimeout;
  final Duration tlsTimeout;
  final Duration readTimeout;
  final Duration testDuration;
  final int minBytes;
  final double throttleThreshold;
  final int reliabilityTries;
  final int reliabilityMin;

  const ScanConfig({
    this.threads = 20,
    this.connectTimeout = const Duration(milliseconds: 2500),
    this.tlsTimeout = const Duration(milliseconds: 3000),
    this.readTimeout = const Duration(milliseconds: 5000),
    this.testDuration = const Duration(seconds: 5),
    this.minBytes = 4096,
    this.throttleThreshold = 0.40,
    this.reliabilityTries = 5,
    this.reliabilityMin = 3,
  });
}

// ─── Result Model ──────────────────────────────────────────────────────────

class ScanResult {
  final String ip;
  final String sni;
  final String cdn;
  final double speed;
  final int latency;
  final double jitter;
  final bool throttled;
  final int throttlePct;
  final int reliability;
  final double score;
  String country;
  String countryFlag;

  ScanResult({
    required this.ip,
    required this.sni,
    required this.cdn,
    required this.speed,
    required this.latency,
    required this.jitter,
    required this.throttled,
    required this.throttlePct,
    required this.reliability,
    required this.score,
    this.country = '',
    this.countryFlag = '🌐',
  });

  String get grade {
    if (throttled) return 'THROTTLED';
    if (speed > 300 && reliability >= 4) return 'S ★★★';
    if (speed > 200) return 'A ★★';
    if (speed > 100) return 'B ★';
    if (speed > 50)  return 'C';
    return 'D';
  }

  String get relBar => '█' * reliability + '░' * (5 - reliability);
}

// ─── Engine ────────────────────────────────────────────────────────────────

class ScannerEngine {
  final ScanConfig config;
  bool _stopped = false;

  ScannerEngine({this.config = const ScanConfig()});

  void stop()  => _stopped = true;
  void reset() => _stopped = false;

  // ── IP Parsing & Private Filter ──────────────────────────────────────────
  static List<String> parseIps(String text) {
    final ipRegex = RegExp(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b');
    final matches = ipRegex.allMatches(text).map((m) => m.group(1)!).toSet().toList();
    // فیلتر IP های خصوصی و reserved
    return matches.where((ip) => !_isPrivate(ip) && _isValidOctet(ip)).toList();
  }

  static bool _isValidOctet(String ip) {
    final parts = ip.split('.').map(int.tryParse).toList();
    if (parts.length != 4) return false;
    return parts.every((p) => p != null && p >= 0 && p <= 255);
  }

  static bool _isPrivate(String ip) {
    final parts = ip.split('.').map(int.tryParse).toList();
    if (parts.length != 4 || parts.any((p) => p == null)) return true;
    final a = parts[0]!, b = parts[1]!;
    if (a == 10) return true;                          // 10.0.0.0/8
    if (a == 172 && b >= 16 && b <= 31) return true;  // 172.16.0.0/12
    if (a == 192 && b == 168) return true;             // 192.168.0.0/16
    if (a == 127) return true;                         // loopback
    if (a == 169 && b == 254) return true;             // link-local
    if (a == 0) return true;                           // 0.0.0.0/8
    if (a == 100 && b >= 64 && b <= 127) return true; // CGNAT
    if (a >= 224) return true;                         // multicast + reserved
    return false;
  }

  // ── TLS Connect ──────────────────────────────────────────────────────────
  Future<SecureSocket?> _tlsConnect(String ip, String sni, Duration timeout) async {
    try {
      return await SecureSocket.connect(
        ip, 443,
        onBadCertificate: (_) => true,
        supportedProtocols: ['http/1.1'],
        timeout: timeout,
      ).timeout(timeout, onTimeout: () => throw TimeoutException('TLS'));
    } catch (_) {
      return null;
    }
  }

  // ── Stage 1: TLS Handshake + latency ─────────────────────────────────────
  Future<(bool, int)> _stageTls(String ip, String sni) async {
    try {
      final t = DateTime.now();
      final socket = await _tlsConnect(ip, sni, config.tlsTimeout);
      if (socket == null) return (false, 9999);
      final ms = DateTime.now().difference(t).inMilliseconds;
      const req = 'HEAD / HTTP/1.1\r\nHost: {SNI}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n';
      socket.write(req.replaceFirst('{SNI}', sni));
      final buf = StringBuffer();
      try {
        await socket.listen((data) {
          buf.write(String.fromCharCodes(data));
          if (buf.toString().contains('HTTP/')) throw 'done';
        }).asFuture().timeout(const Duration(seconds: 2));
      } catch (_) {}
      await socket.close();
      if (buf.toString().contains('HTTP/')) return (true, ms);
      if (ms < config.tlsTimeout.inMilliseconds * 0.9) return (true, ms);
    } catch (_) {}
    return (false, 9999);
  }

  // ── Stage 2: Reliability — چند بار تست بزن ────────────────────────────
  Future<(bool, int, int)> _stageReliability(String ip, String sni) async {
    int success = 0;
    final lats = <int>[];
    for (int i = 0; i < config.reliabilityTries; i++) {
      if (_stopped) break;
      final (ok, ms) = await _stageTls(ip, sni);
      if (ok) { success++; lats.add(ms); }
      await Future.delayed(const Duration(milliseconds: 100));
    }
    final reliable = success >= config.reliabilityMin;
    final avgLat = lats.isEmpty ? 9999 : lats.reduce((a, b) => a + b) ~/ lats.length;
    return (reliable, success, avgLat);
  }

  // ── Stage 3: Bandwidth measurement ───────────────────────────────────────
  Future<Map<String, dynamic>?> _stageBandwidth(String ip, String sni, String endpoint) async {
    try {
      final socket = await _tlsConnect(ip, sni, config.connectTimeout);
      if (socket == null) return null;
      final req = 'GET $endpoint HTTP/1.1\r\nHost: $sni\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n';
      socket.write(req);
      final start = DateTime.now();
      int total = 0;
      int? firstByteMs;
      final samples = <double>[];
      DateTime lastSample = start;
      final completer = Completer<void>();
      final sub = socket.listen(
        (data) {
          final now = DateTime.now();
          firstByteMs ??= now.difference(start).inMilliseconds;
          total += data.length;
          if (now.difference(lastSample).inMilliseconds >= 1000) {
            final elapsed = now.difference(start).inMilliseconds / 1000.0;
            samples.add((total / 1024) / max(elapsed, 0.001));
            lastSample = now;
          }
          if (now.difference(start) >= config.testDuration) {
            if (!completer.isCompleted) completer.complete();
          }
        },
        onDone: () { if (!completer.isCompleted) completer.complete(); },
        onError: (_) { if (!completer.isCompleted) completer.complete(); },
      );
      await completer.future.timeout(
        config.testDuration + const Duration(seconds: 2),
        onTimeout: () {},
      );
      await sub.cancel();
      await socket.close();
      final elapsed = DateTime.now().difference(start).inMilliseconds / 1000.0;
      if (elapsed <= 0 || total < config.minBytes) return null;
      final speed = (total / 1024) / elapsed;
      final latency = firstByteMs ?? 0;
      double jitter = 0;
      if (samples.length > 1) {
        final mean = samples.reduce((a, b) => a + b) / samples.length;
        final variance = samples.map((s) => pow(s - mean, 2)).reduce((a, b) => a + b) / samples.length;
        jitter = sqrt(variance);
      }
      bool throttled = false;
      int throttlePct = 0;
      if (samples.length >= 3) {
        final mid = samples.length ~/ 2;
        final fAvg = samples.sublist(0, mid).reduce((a, b) => a + b) / mid;
        final sAvg = samples.sublist(mid).reduce((a, b) => a + b) / (samples.length - mid);
        if (fAvg > 0) {
          final drop = (fAvg - sAvg) / fAvg;
          throttlePct = (drop * 100).round();
          throttled = drop > config.throttleThreshold;
        }
      }
      return {
        'speed': double.parse(speed.toStringAsFixed(1)),
        'latency': latency,
        'jitter': double.parse(jitter.toStringAsFixed(1)),
        'throttled': throttled,
        'throttlePct': throttlePct,
      };
    } catch (_) {
      return null;
    }
  }

  // ── CDN Detection ─────────────────────────────────────────────────────────
  Future<(String, List<String>)> _detectCdn(String ip) async {
    for (final probe in ['aparat.com', 'a248.e.akamai.net', 'speed.cloudflare.com']) {
      try {
        final socket = await _tlsConnect(ip, probe, config.connectTimeout);
        if (socket == null) continue;
        final req = 'HEAD / HTTP/1.1\r\nHost: $probe\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n';
        socket.write(req);
        final buf = StringBuffer();
        try {
          await socket.listen((data) {
            buf.write(String.fromCharCodes(data));
            if (buf.toString().contains('\r\n\r\n')) throw 'done';
          }).asFuture().timeout(const Duration(seconds: 2));
        } catch (_) {}
        await socket.close();
        final hdrs = buf.toString().toLowerCase();
        String srv = '';
        for (final line in hdrs.split('\r\n')) {
          if (line.startsWith('server:')) {
            srv = line.split(':').skip(1).join(':').trim();
            break;
          }
        }
        for (final entry in cdnMap.entries) {
          if (entry.key == 'Iranian') continue;
          final info = entry.value;
          if (info.headers.any((h) => hdrs.contains(h)) ||
              info.server.any((s) => srv.contains(s))) {
            final rest = allSnis.where((s) => !info.snis.contains(s)).toList();
            return (entry.key, [...info.snis, ...rest]);
          }
        }
      } catch (_) {}
    }
    return ('Unknown', allSnis);
  }

  // ── Score ─────────────────────────────────────────────────────────────────
  static double calcScore(double speed, int latency, double jitter, bool throttled, int reliability) {
    final s   = min(speed / 500, 1.0) * 55;
    final l   = max(0, 1 - latency / 800) * 20;
    final j   = max(0.0, 1 - jitter / max(speed, 1)) * 10;
    final t   = throttled ? 0.0 : 5.0;
    final rel = (reliability / 5) * 10;
    return double.parse((s + l + j + t + rel).toStringAsFixed(1));
  }

  // ── GeoIP از دیتابیس آفلاین ───────────────────────────────────────────────
  void _applyGeo(List<ScanResult> results) {
    final geo = GeoIPOffline();
    for (final r in results) {
      final (name, flag) = geo.lookupFull(r.ip);
      r.country     = name;
      r.countryFlag = flag;
    }
  }

  // ── Retest single IP ──────────────────────────────────────────────────────
  Future<ScanResult?> retestIp(ScanResult original) async {
    reset();
    final sni      = original.sni;
    final endpoint = cdnMap[original.cdn]?.endpoint ?? '/';
    final (ok, _)  = await _stageTls(original.ip, sni);
    if (!ok) return null;
    final bw = await _stageBandwidth(original.ip, sni, endpoint);
    if (bw == null) return null;
    final score = calcScore(
      bw['speed'], bw['latency'], bw['jitter'], bw['throttled'], original.reliability);
    return ScanResult(
      ip: original.ip, sni: sni, cdn: original.cdn,
      speed: bw['speed'], latency: bw['latency'],
      jitter: bw['jitter'], throttled: bw['throttled'],
      throttlePct: bw['throttlePct'], reliability: original.reliability,
      score: score, country: original.country, countryFlag: original.countryFlag,
    );
  }

  // ── Mode 1: Simple ────────────────────────────────────────────────────────
  Future<void> scanMode1({
    required List<String> ips,
    required void Function(int done, int total) onProgress,
    required void Function(ScanResult) onResult,
    required void Function(List<ScanResult>) onDone,
    void Function(int percent)? onNotify,
  }) async {
    reset();
    const sni = 'google.com';
    const endpoint = '/';
    final results = <ScanResult>[];
    int done = 0;
    final semaphore = _Semaphore(config.threads);

    final futures = ips.map((ip) async {
      await semaphore.acquire();
      try {
        if (!_stopped) {
          try {
            await Future(() async {
              final (ok, _) = await _stageTls(ip, sni);
              if (ok && !_stopped) {
                final bw = await _stageBandwidth(ip, sni, endpoint);
                if (bw != null && !_stopped) {
                  final score = calcScore(
                    bw['speed'], bw['latency'], bw['jitter'], bw['throttled'], 5);
                  final r = ScanResult(
                    ip: ip, sni: sni, cdn: 'Auto',
                    speed: bw['speed'], latency: bw['latency'],
                    jitter: bw['jitter'], throttled: bw['throttled'],
                    throttlePct: bw['throttlePct'], reliability: 5, score: score,
                  );
                  results.add(r);
                  onResult(r);
                }
              }
            }).timeout(const Duration(seconds: 20), onTimeout: () {});
          } catch (_) {}
        }
      } finally {
        done++;
        onProgress(done, ips.length);
        final pct = (done / ips.length * 100).round();
        if (pct % 25 == 0 || pct >= 100) onNotify?.call(pct);
        semaphore.release();
      }
    });

    await Future.wait(futures.toList());
    _applyGeo(results);                               // ← GeoIP آفلاین
    results.sort((a, b) => b.score.compareTo(a.score));
    onDone(results);
  }

  // ── Mode 2: Auto-SNI ──────────────────────────────────────────────────────
  Future<void> scanMode2({
    required List<String> ips,
    required void Function(int done, int total) onProgress,
    required void Function(ScanResult) onResult,
    required void Function(List<ScanResult>) onDone,
    List<String>? customSnis,
    void Function(int percent)? onNotify,
  }) async {
    reset();
    final results = <ScanResult>[];
    int done = 0;
    final semaphore = _Semaphore(config.threads);

    final futures = ips.map((ip) async {
      await semaphore.acquire();
      try {
        if (!_stopped) {
          try {
            await Future(() async {
              List<String> sniList;
              String cdnName;

              if (customSnis != null && customSnis.isNotEmpty) {
                sniList = customSnis;
                cdnName = 'Custom';
              } else {
                final detected = await _detectCdn(ip);
                cdnName = detected.$1;
                sniList = detected.$2;
              }

              final endpoint = cdnMap[cdnName]?.endpoint ?? '/';

              for (final sni in sniList) {
                if (_stopped) break;
                final (ok, _) = await _stageTls(ip, sni);
                if (!ok) continue;
                final (reliable, relCount, _) = await _stageReliability(ip, sni);
                if (!reliable || _stopped) continue;
                final bw = await _stageBandwidth(ip, sni, endpoint);
                if (bw == null) continue;
                final score = calcScore(
                  bw['speed'], bw['latency'], bw['jitter'], bw['throttled'], relCount);
                final r = ScanResult(
                  ip: ip, sni: sni, cdn: cdnName,
                  speed: bw['speed'], latency: bw['latency'],
                  jitter: bw['jitter'], throttled: bw['throttled'],
                  throttlePct: bw['throttlePct'], reliability: relCount, score: score,
                );
                results.add(r);
                onResult(r);
              }
            }).timeout(const Duration(seconds: 60), onTimeout: () {});
          } catch (_) {}
        }
      } finally {
        done++;
        onProgress(done, ips.length);
        final pct = (done / ips.length * 100).round();
        if (pct % 25 == 0 || pct >= 100) onNotify?.call(pct);
        semaphore.release();
      }
    });

    await Future.wait(futures.toList());
    _applyGeo(results);                               // ← GeoIP آفلاین
    results.sort((a, b) => b.score.compareTo(a.score));
    onDone(results);
  }
}

// ─── Semaphore ─────────────────────────────────────────────────────────────

class _Semaphore {
  final int maxCount;
  int _count = 0;
  final _queue = <Completer<void>>[];

  _Semaphore(this.maxCount);

  Future<void> acquire() async {
    if (_count < maxCount) { _count++; return; }
    final c = Completer<void>();
    _queue.add(c);
    await c.future;
  }

  void release() {
    if (_queue.isNotEmpty) {
      _queue.removeAt(0).complete();
    } else {
      _count--;
    }
  }
}
