// lib/engine/sni_engine.dart
// SNI is fixed to www.google.com for Shir Khorshid CDN mode.
// CDN header detection removed — irrelevant for tunnel survivability.

import '../models/provider_type.dart';

final providerSnis = {
  ProviderType.cloudflare: ['speed.cloudflare.com', 'cloudflare.com'],
  ProviderType.akamai:     ['a248.e.akamai.net'],
  ProviderType.fastly:     ['github.com'],
};

ProviderType detectProvider(String serverHeader) {
  final s = serverHeader.toLowerCase();
  if (s.contains('cloudflare'))  return ProviderType.cloudflare;
  if (s.contains('akamaighost')) return ProviderType.akamai;
  if (s.contains('fastly'))      return ProviderType.fastly;
  return ProviderType.unknown;
}
