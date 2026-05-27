// lib/engine/range/subnet_sampler.dart
// Real CIDR parsing and IP sampling — no placeholders

import 'dart:math';

class SubnetSampler {
  final Random _rng = Random();

  /// Expand ALL IPs in a CIDR — returns every usable host address
  List<String> sequential(String cidr) {
    return _expandCidr(cidr, maxCount: null);
  }

  /// Random sample of [count] unique IPs from the CIDR
  List<String> sample(String cidr, int count) {
    final all = _expandCidr(cidr, maxCount: null);
    if (all.isEmpty) return [];
    if (count >= all.length) return all;
    // Fisher-Yates shuffle, take first [count]
    final list = List<String>.from(all);
    for (int i = list.length - 1; i > 0; i--) {
      final j = _rng.nextInt(i + 1);
      final tmp = list[i];
      list[i] = list[j];
      list[j] = tmp;
    }
    return list.take(count).toList();
  }

  /// Sequential if ≤512 IPs, otherwise random sample
  List<String> smart(String cidr, {int maxSample = 300}) {
    final parts = cidr.split('/');
    if (parts.length != 2) return [];
    final prefix = int.tryParse(parts[1]) ?? 32;
    final total = 1 << (32 - prefix);
    if (total <= 512) {
      return _expandCidr(cidr, maxCount: null);
    }
    return sample(cidr, maxSample);
  }

  /// Real CIDR expansion
  List<String> _expandCidr(String cidr, {int? maxCount}) {
    final parts = cidr.split('/');
    if (parts.length != 2) return [];
    final ipStr = parts[0];
    final prefix = int.tryParse(parts[1]);
    if (prefix == null || prefix < 0 || prefix > 32) return [];

    final octets = ipStr.split('.');
    if (octets.length != 4) return [];
    final o = octets.map(int.tryParse).toList();
    if (o.any((x) => x == null || x < 0 || x > 255)) return [];

    final base = (o[0]! << 24) | (o[1]! << 16) | (o[2]! << 8) | o[3]!;
    final mask = prefix == 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF;
    final network = base & mask;
    final total = 1 << (32 - prefix);

    // For /31 and /32: no network/broadcast exclusion per RFC 3021
    final startOffset = prefix >= 31 ? 0 : 1;
    final endOffset   = prefix >= 31 ? total : total - 1;

    final ips = <String>[];
    for (int i = startOffset; i < endOffset; i++) {
      if (maxCount != null && ips.length >= maxCount) break;
      final addr = network + i;
      final ip = '${(addr >> 24) & 0xFF}.'
                 '${(addr >> 16) & 0xFF}.'
                 '${(addr >> 8) & 0xFF}.'
                 '${addr & 0xFF}';
      if (!isPrivate(ip)) ips.add(ip);
    }
    return ips;
  }

  /// Reject RFC-1918, loopback, CGNAT, link-local, multicast, reserved
  static bool isPrivate(String ip) {
    final parts = ip.split('.');
    if (parts.length != 4) return true;
    final o = parts.map(int.tryParse).toList();
    if (o.any((x) => x == null)) return true;
    final a = o[0]!, b = o[1]!;

    // Loopback: 127.0.0.0/8
    if (a == 127) return true;
    // RFC-1918 private:
    if (a == 10) return true;                            // 10.0.0.0/8
    if (a == 172 && b >= 16 && b <= 31) return true;    // 172.16.0.0/12
    if (a == 192 && b == 168) return true;               // 192.168.0.0/16
    // CGNAT: 100.64.0.0/10
    if (a == 100 && b >= 64 && b <= 127) return true;
    // Link-local: 169.254.0.0/16
    if (a == 169 && b == 254) return true;
    // Multicast: 224.0.0.0/4
    if (a >= 224 && a <= 239) return true;
    // Reserved/broadcast: 240.0.0.0/4
    if (a >= 240) return true;
    // 0.0.0.0/8
    if (a == 0) return true;
    return false;
  }
}
