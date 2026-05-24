// lib/engine/sni_engine.dart
import '../models/provider_type.dart';

final providerSnis = {
  ProviderType.cloudflare: [
    'speed.cloudflare.com',
    'cloudflare.com',
  ],

  ProviderType.akamai: [
    'a248.e.akamai.net',
    'download.windowsupdate.com',
  ],

  ProviderType.fastly: [
    'github.com',
    'githubusercontent.com',
  ],
};

ProviderType detectProvider(String serverHeader) {
  final s = serverHeader.toLowerCase();

  if (s.contains('cloudflare'))  return ProviderType.cloudflare;
  if (s.contains('akamaighost')) return ProviderType.akamai;
  if (s.contains('fastly'))      return ProviderType.fastly;

  return ProviderType.unknown;
}
