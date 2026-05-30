import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:http/http.dart' as http;

class TruthResult {
  final String domain;
  final List<String> ips;
  final String provider;
  final bool fromCache;

  const TruthResult({
    required this.domain,
    required this.ips,
    required this.provider,
    this.fromCache = false,
  });

  bool get hasRecords => ips.isNotEmpty;
}

class SourceOfTruth {
  final List<String> providers;
  final Duration timeout;
  final _cache = <String, TruthResult>{};

  SourceOfTruth({
    required this.providers,
    this.timeout = const Duration(milliseconds: 4000),
  });

  Future<TruthResult?> resolve(String domain) async {
    if (_cache.containsKey(domain)) {
      final cached = _cache[domain]!;
      return TruthResult(
        domain: cached.domain,
        ips: cached.ips,
        provider: cached.provider,
        fromCache: true,
      );
    }
    for (final providerUrl in providers) {
      final result = await _queryProvider(providerUrl, domain);
      if (result != null) {
        _cache[domain] = result;
        return result;
      }
    }
    return null;
  }

  Future<void> warmCache(List<String> domains) async {
    await Future.wait(
      domains.map((d) => resolve(d)),
      eagerError: false,
    );
  }

  Future<TruthResult?> _queryProvider(String baseUrl, String domain) async {
    try {
      final uri = Uri.parse(baseUrl).replace(
        queryParameters: {'name': domain, 'type': 'A'},
      );
      final response = await http.get(
        uri,
        headers: {'Accept': 'application/dns-json'},
      ).timeout(timeout);
      if (response.statusCode != 200) return null;
      final jsonData = jsonDecode(response.body) as Map<String, dynamic>;
      final status = jsonData['Status'] as int? ?? -1;
      if (status == 3) {
        return TruthResult(domain: domain, ips: [], provider: baseUrl);
      }
      if (status != 0) return null;
      final answers = (jsonData['Answer'] as List<dynamic>? ?? [])
          .cast<Map<String, dynamic>>();
      final ips = answers
          .where((a) => (a['type'] as int? ?? 0) == 1)
          .map((a) => a['data'] as String? ?? '')
          .where((ip) => ip.isNotEmpty)
          .toList();
      return TruthResult(domain: domain, ips: ips, provider: baseUrl);
    } on SocketException {
      return null;
    } on TimeoutException {
      return null;
    } catch (_) {
      return null;
    }
  }

  Future<Map<String, bool>> testProviders() async {
    final results = <String, bool>{};
    await Future.wait(
      providers.map((url) async {
        final r = await _queryProvider(url, 'example.com');
        results[url] = r != null;
      }),
    );
    return results;
  }

  static bool ipsOverlap(List<String> received, List<String> truth) {
    if (truth.isEmpty || received.isEmpty) return false;
    return received.any(truth.contains);
  }
}
