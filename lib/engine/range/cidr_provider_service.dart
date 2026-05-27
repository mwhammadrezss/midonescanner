// lib/engine/range/cidr_provider_service.dart
// All 6 CDN providers with real CIDR ranges and live fetch support

import 'dart:convert';
import 'dart:io';

enum RangeCdnProvider { cloudflare, fastly, google, microsoft, akamai, gcore }

class RangeCdnMeta {
  final RangeCdnProvider provider;
  final String name;
  final String emoji;
  final String? fetchUrl;
  final List<String> fallbackCidrs;

  const RangeCdnMeta({
    required this.provider,
    required this.name,
    required this.emoji,
    this.fetchUrl,
    required this.fallbackCidrs,
  });
}

const kRangeCdnProviders = <RangeCdnMeta>[
  RangeCdnMeta(
    provider: RangeCdnProvider.cloudflare,
    name: 'Cloudflare',
    emoji: '☁️',
    fetchUrl: 'https://www.cloudflare.com/ips-v4',
    fallbackCidrs: [
      '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13',
      '198.41.128.0/17', '162.158.0.0/15', '173.245.48.0/20',
      '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
      '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20',
      '188.114.96.0/20', '197.234.240.0/22', '131.0.72.0/22',
    ],
  ),
  RangeCdnMeta(
    provider: RangeCdnProvider.fastly,
    name: 'Fastly',
    emoji: '⚡',
    fetchUrl: 'https://api.fastly.com/public-ip-list',
    fallbackCidrs: [
      '23.235.32.0/20', '43.249.72.0/22', '103.244.50.0/24',
      '103.245.222.0/23', '103.245.224.0/24', '104.156.80.0/20',
      '140.248.64.0/18', '140.248.128.0/17', '146.75.0.0/18',
      '151.101.0.0/16', '157.52.64.0/18', '167.82.0.0/17',
      '167.82.128.0/20', '172.111.64.0/18', '185.31.16.0/22',
      '199.27.72.0/21', '199.232.0.0/16',
    ],
  ),
  RangeCdnMeta(
    provider: RangeCdnProvider.google,
    name: 'Google',
    emoji: '🔵',
    fetchUrl: 'https://www.gstatic.com/ipranges/goog.json',
    fallbackCidrs: [
      '8.8.8.0/24', '74.125.0.0/16', '66.249.80.0/20',
      '108.177.8.0/21', '172.217.0.0/16', '216.58.192.0/19',
      '64.233.160.0/19', '66.102.0.0/20', '209.85.128.0/17',
    ],
  ),
  RangeCdnMeta(
    provider: RangeCdnProvider.microsoft,
    name: 'Microsoft',
    emoji: '🪟',
    fetchUrl: null,
    fallbackCidrs: [
      '13.107.64.0/18', '13.107.128.0/22', '23.103.160.0/20',
      '40.96.0.0/13', '40.104.0.0/15', '52.96.0.0/14',
      '52.100.0.0/14', '104.40.0.0/13', '132.245.0.0/16',
      '150.171.32.0/22', '204.79.197.215/32',
    ],
  ),
  RangeCdnMeta(
    provider: RangeCdnProvider.akamai,
    name: 'Akamai',
    emoji: '🌐',
    fetchUrl: null,
    fallbackCidrs: [
      '23.32.0.0/20', '23.32.16.0/20', '23.32.32.0/20',
      '23.64.0.0/20', '23.64.16.0/20', '23.64.32.0/20',
      '23.192.0.0/20', '23.192.16.0/20', '96.16.0.0/20',
      '72.246.0.0/20', '184.50.0.0/20', '2.16.0.0/20',
      '92.122.0.0/20', '60.254.0.0/20',
    ],
  ),
  RangeCdnMeta(
    provider: RangeCdnProvider.gcore,
    name: 'Gcore',
    emoji: '🟣',
    fetchUrl: null,
    fallbackCidrs: [
      '92.223.96.0/20', '5.188.208.0/22', '94.156.128.0/22',
      '199.48.168.0/22', '209.200.0.0/22', '77.83.240.0/22',
      '45.134.212.0/22', '185.112.83.0/24', '92.223.112.0/20',
    ],
  ),
];

class CidrProviderService {
  /// Fetch live CIDRs from provider URL, fallback to hardcoded list
  Future<List<String>> fetchCidrs(RangeCdnMeta meta) async {
    if (meta.fetchUrl == null) return meta.fallbackCidrs;

    try {
      final client = HttpClient()
        ..connectionTimeout = const Duration(seconds: 8);
      final request = await client.getUrl(Uri.parse(meta.fetchUrl!));
      final response =
          await request.close().timeout(const Duration(seconds: 8));
      final body = await response.transform(utf8.decoder).join();
      client.close();

      List<String> cidrs = [];

      switch (meta.provider) {
        case RangeCdnProvider.cloudflare:
          // Plain text: one CIDR per line
          cidrs = body
              .split('\n')
              .map((l) => l.trim())
              .where((l) => l.isNotEmpty && l.contains('.') && l.contains('/'))
              .toList();
          break;

        case RangeCdnProvider.fastly:
          // JSON: {"addresses": ["x.x.x.x/yy", ...], "ipv6_addresses": [...]}
          final json = jsonDecode(body) as Map<String, dynamic>;
          final addresses = json['addresses'] as List<dynamic>? ?? [];
          cidrs = addresses
              .map((e) => e.toString())
              .where((e) => e.contains('.') && e.contains('/'))
              .toList();
          break;

        case RangeCdnProvider.google:
          // JSON: {"prefixes": [{"ipv4Prefix": "..."}]}
          final json = jsonDecode(body) as Map<String, dynamic>;
          final prefixes = json['prefixes'] as List<dynamic>? ?? [];
          cidrs = prefixes
              .map((p) => (p as Map)['ipv4Prefix'] as String?)
              .whereType<String>()
              .toList();
          break;

        default:
          break;
      }

      if (cidrs.isNotEmpty) return cidrs;
    } catch (_) {
      // Fetch failed — use fallback
    }

    return meta.fallbackCidrs;
  }

  /// Filter to IPv4 only, sort smallest prefix first (/24 before /16),
  /// return top [maxCount]
  List<String> selectBestCidrs(List<String> allCidrs, {int maxCount = 12}) {
    final ipv4 = allCidrs
        .where((c) => c.contains('.') && c.contains('/'))
        .toList();

    ipv4.sort((a, b) {
      final pa = int.tryParse(a.split('/').last) ?? 0;
      final pb = int.tryParse(b.split('/').last) ?? 0;
      return pb.compareTo(pa); // higher prefix = smaller range = first
    });

    return ipv4.take(maxCount).toList();
  }
}
