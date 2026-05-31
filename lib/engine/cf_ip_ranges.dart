// lib/engine/cf_ip_ranges.dart
// ─── Cloudflare IP ranges (embedded + live fetch) ────────────────────────────
// Mirrors SenPaiScanner internal/ipsrc/ipsrc.go — adapted for Dart/Flutter.
//
// Built-in ranges from https://www.cloudflare.com/ips-v4/ (as of 2024)
// Live update: fetches fresh ranges from Cloudflare on demand.

import 'dart:math';
import 'dart:io';
import 'dart:async';

// ─── Built-in Cloudflare IPv4 ranges ─────────────────────────────────────────
const kCfRangesV4 = [
  '173.245.48.0/20',
  '103.21.244.0/22',
  '103.22.200.0/22',
  '103.31.4.0/22',
  '141.101.64.0/18',
  '108.162.192.0/18',
  '190.93.240.0/20',
  '188.114.96.0/20',
  '197.234.240.0/22',
  '198.41.128.0/17',
  '162.158.0.0/15',
  '104.16.0.0/13',
  '104.24.0.0/14',
  '172.64.0.0/13',
  '131.0.72.0/22',
];

// ─── Built-in Cloudflare IPv6 ranges ─────────────────────────────────────────
const kCfRangesV6 = [
  '2400:cb00::/32',
  '2606:4700::/32',
  '2803:f800::/32',
  '2405:b500::/32',
  '2405:8100::/32',
  '2a06:98c0::/29',
  '2c0f:f248::/32',
];

/// Total IPv4 address count across all CF ranges.
int get cfTotalV4IpCount {
  int total = 0;
  for (final cidr in kCfRangesV4) {
    total += _cidrSize(cidr);
  }
  return total;
}

int _cidrSize(String cidr) {
  final parts = cidr.split('/');
  if (parts.length != 2) return 0;
  final prefix = int.tryParse(parts[1]) ?? 32;
  return 1 << (32 - prefix);
}

// ─── IP sampling ─────────────────────────────────────────────────────────────

/// Samples [count] random unique IPv4 addresses from Cloudflare's ranges.
/// Mirrors SenPai Source.Stream() — deduplication via a Set.
List<String> sampleCfIps({
  required int count,
  List<String>? cidrFilter, // if non-null, only sample from these CIDRs
}) {
  final ranges = cidrFilter ?? kCfRangesV4;
  if (ranges.isEmpty) return [];

  final rng = Random();
  final seen = <String>{};
  final result = <String>[];

  // Parse all ranges once
  final parsed = <_CidrRange>[];
  for (final cidr in ranges) {
    final r = _CidrRange.parse(cidr);
    if (r != null) parsed.add(r);
  }
  if (parsed.isEmpty) return [];

  // Total weight for proportional sampling
  final weights = parsed.map((r) => r.size).toList();
  final totalWeight = weights.fold<int>(0, (a, b) => a + b);

  int attempts = 0;
  final maxAttempts = count * 5; // guard against infinite loop on tiny ranges

  while (result.length < count && attempts < maxAttempts) {
    attempts++;
    // Pick a range proportionally to its size
    int pick = rng.nextInt(totalWeight);
    _CidrRange? chosen;
    for (int i = 0; i < parsed.length; i++) {
      pick -= weights[i];
      if (pick < 0) { chosen = parsed[i]; break; }
    }
    chosen ??= parsed.last;

    final ip = chosen.randomIp(rng);
    if (seen.add(ip)) result.add(ip);
  }

  return result;
}

/// Fetches the latest Cloudflare IP ranges from cloudflare.com.
/// Returns the updated v4 and v6 lists, or throws on network error.
Future<({List<String> v4, List<String> v6})> fetchLatestCfRanges({
  Duration timeout = const Duration(seconds: 10),
}) async {
  Future<List<String>> fetch(String url) async {
    final client = HttpClient();
    client.connectionTimeout = timeout;
    try {
      final req = await client.getUrl(Uri.parse(url));
      final resp = await req.close();
      if (resp.statusCode != 200) {
        throw HttpException('HTTP ${resp.statusCode}', uri: Uri.parse(url));
      }
      final body = await resp.transform(const SystemEncoding().decoder).join();
      return body
          .split('\n')
          .map((l) => l.trim())
          .where((l) => l.isNotEmpty && !l.startsWith('#'))
          .toList();
    } finally {
      client.close();
    }
  }

  final v4 = await fetch('https://www.cloudflare.com/ips-v4/');
  final v6 = await fetch('https://www.cloudflare.com/ips-v6/');
  return (v4: v4, v6: v6);
}

// ─── Internal CIDR range model ────────────────────────────────────────────────

class _CidrRange {
  final int baseIp;   // network address as 32-bit int
  final int mask;     // subnet mask as 32-bit int
  final int size;     // number of IPs in range

  const _CidrRange({required this.baseIp, required this.mask, required this.size});

  static _CidrRange? parse(String cidr) {
    final parts = cidr.split('/');
    if (parts.length != 2) return null;
    final prefix = int.tryParse(parts[1]);
    if (prefix == null || prefix < 0 || prefix > 32) return null;

    final ipParts = parts[0].split('.');
    if (ipParts.length != 4) return null;

    int ip = 0;
    for (final part in ipParts) {
      final b = int.tryParse(part);
      if (b == null || b < 0 || b > 255) return null;
      ip = (ip << 8) | b;
    }

    final mask = prefix == 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF;
    final base = ip & mask;
    final size = 1 << (32 - prefix);

    return _CidrRange(baseIp: base, mask: mask, size: size);
  }

  /// Returns a random IP within this range as a string.
  String randomIp(Random rng) {
    final hostMask = ~mask & 0xFFFFFFFF;
    final offset = rng.nextInt(size).toInt();
    final ip = baseIp | (offset & hostMask);
    return _intToIp(ip);
  }
}

String _intToIp(int ip) {
  return '${(ip >> 24) & 0xFF}.'
      '${(ip >> 16) & 0xFF}.'
      '${(ip >> 8) & 0xFF}.'
      '${ip & 0xFF}';
}
