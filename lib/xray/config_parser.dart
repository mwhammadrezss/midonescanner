// lib/xray/config_parser.dart
// ─── Xray / V2Ray config parser (vless:// and trojan://) ─────────────────────
// Mirrors SenPaiScanner internal/xraytest/parser.go — adapted for Dart/Flutter.

/// Parsed parameters from a VLESS or Trojan share URL.
class XrayConfig {
  final String protocol;     // "vless" or "trojan"

  // VLESS-specific
  final String uuid;
  final String encryption;
  final String flow;

  // Trojan-specific
  final String password;

  // Common
  final String address;
  final int port;

  // Transport
  final String network;      // ws, grpc, xhttp, tcp
  final String path;
  final String host;
  final String serviceName;  // gRPC
  final String mode;         // gRPC multi/gun, xhttp auto
  final String authority;    // gRPC

  // TLS
  final String security;     // tls, reality, none
  final String sni;
  final String fingerprint;
  final List<String> alpn;
  final bool insecure;

  // Metadata
  final String remark;

  const XrayConfig({
    required this.protocol,
    this.uuid = '',
    this.encryption = 'none',
    this.flow = '',
    this.password = '',
    required this.address,
    required this.port,
    this.network = 'tcp',
    this.path = '/',
    this.host = '',
    this.serviceName = '',
    this.mode = '',
    this.authority = '',
    this.security = 'none',
    this.sni = '',
    this.fingerprint = '',
    this.alpn = const [],
    this.insecure = false,
    this.remark = '',
  });

  /// Returns a copy with address (and optionally port) replaced.
  XrayConfig withAddress(String newAddress, {int? newPort}) => XrayConfig(
        protocol: protocol,
        uuid: uuid,
        encryption: encryption,
        flow: flow,
        password: password,
        address: newAddress,
        port: newPort ?? port,
        network: network,
        path: path,
        host: host,
        serviceName: serviceName,
        mode: mode,
        authority: authority,
        security: security,
        sni: sni,
        fingerprint: fingerprint,
        alpn: alpn,
        insecure: insecure,
        remark: remark,
      );

  /// Effective SNI — uses sni field, then host, then address.
  String get effectiveSni {
    if (sni.isNotEmpty) return sni;
    if (host.isNotEmpty) return host;
    return address;
  }

  @override
  String toString() => 'XrayConfig($protocol, $address:$port, $network, sni=$sni)';
}

/// Auto-detects vless:// or trojan:// and parses the URL.
/// Throws [ArgumentError] if the scheme is unknown.
XrayConfig parseProxyUrl(String raw) {
  raw = raw.trim();
  if (raw.startsWith('vless://')) return parseVless(raw);
  if (raw.startsWith('trojan://')) return parseTrojan(raw);
  throw ArgumentError('Unsupported URL scheme — must start with vless:// or trojan://');
}

/// Parses a vless:// share URL.
XrayConfig parseVless(String raw) {
  if (!raw.startsWith('vless://')) {
    throw ArgumentError('Not a vless:// URL');
  }
  raw = raw.substring('vless://'.length);

  // Split remark (#)
  String remark = '';
  final hashIdx = raw.lastIndexOf('#');
  if (hashIdx != -1) {
    remark = Uri.decodeComponent(raw.substring(hashIdx + 1));
    raw = raw.substring(0, hashIdx);
  }

  // Split query params (?)
  final Map<String, String> params = {};
  final qIdx = raw.indexOf('?');
  if (qIdx != -1) {
    final queryStr = raw.substring(qIdx + 1);
    raw = raw.substring(0, qIdx);
    Uri.splitQueryString(queryStr).forEach((k, v) => params[k] = v);
  }

  // Split uuid@host:port
  final atIdx = raw.indexOf('@');
  if (atIdx == -1) throw ArgumentError('Missing @ in vless URL');
  final uuid = raw.substring(0, atIdx);
  final hostPort = raw.substring(atIdx + 1);

  final (host, portStr) = _splitHostPort(hostPort);
  final port = int.tryParse(portStr) ?? (throw ArgumentError('Invalid port: $portStr'));

  final network = params['type'] ?? 'tcp';
  String path = '/';
  String wsHost = '';
  String serviceName = '';
  String grpcMode = '';
  String authority = '';

  switch (network) {
    case 'ws':
      path = params['path'] ?? '/';
      wsHost = params['host'] ?? (params['sni'] ?? '');
      break;
    case 'grpc':
      serviceName = params['serviceName'] ?? '';
      authority = params['authority'] ?? '';
      grpcMode = params['mode'] ?? 'gun';
      break;
    case 'xhttp':
    case 'splithttp':
      path = params['path'] ?? '/';
      wsHost = params['host'] ?? (params['sni'] ?? '');
      grpcMode = params['mode'] ?? 'auto';
      break;
  }

  final alpnStr = params['alpn'] ?? '';
  final alpn = alpnStr.isNotEmpty ? alpnStr.split(',') : <String>[];

  return XrayConfig(
    protocol: 'vless',
    uuid: uuid,
    encryption: params['encryption'] ?? 'none',
    flow: params['flow'] ?? '',
    address: host,
    port: port,
    network: network,
    path: path,
    host: wsHost,
    serviceName: serviceName,
    mode: grpcMode,
    authority: authority,
    security: params['security'] ?? 'none',
    sni: params['sni'] ?? '',
    fingerprint: params['fp'] ?? '',
    alpn: alpn,
    insecure: params['insecure'] == '1' || params['allowInsecure'] == '1',
    remark: remark,
  );
}

/// Parses a trojan:// share URL.
XrayConfig parseTrojan(String raw) {
  if (!raw.startsWith('trojan://')) {
    throw ArgumentError('Not a trojan:// URL');
  }
  raw = raw.substring('trojan://'.length);

  String remark = '';
  final hashIdx = raw.lastIndexOf('#');
  if (hashIdx != -1) {
    remark = Uri.decodeComponent(raw.substring(hashIdx + 1));
    raw = raw.substring(0, hashIdx);
  }

  final Map<String, String> params = {};
  final qIdx = raw.indexOf('?');
  if (qIdx != -1) {
    final queryStr = raw.substring(qIdx + 1);
    raw = raw.substring(0, qIdx);
    Uri.splitQueryString(queryStr).forEach((k, v) => params[k] = v);
  }

  final atIdx = raw.indexOf('@');
  if (atIdx == -1) throw ArgumentError('Missing @ in trojan URL');
  final password = Uri.decodeComponent(raw.substring(0, atIdx));
  final hostPort = raw.substring(atIdx + 1);

  final (host, portStr) = _splitHostPort(hostPort);
  final port = int.tryParse(portStr) ?? (throw ArgumentError('Invalid port: $portStr'));

  final network = params['type'] ?? 'tcp';
  String path = '/';
  String wsHost = '';
  String serviceName = '';
  String grpcMode = '';
  String authority = '';

  switch (network) {
    case 'ws':
      path = params['path'] ?? '/';
      wsHost = params['host'] ?? (params['sni'] ?? '');
      break;
    case 'grpc':
      serviceName = params['serviceName'] ?? '';
      authority = params['authority'] ?? '';
      grpcMode = params['mode'] ?? 'gun';
      break;
    case 'xhttp':
    case 'splithttp':
      path = params['path'] ?? '/';
      wsHost = params['host'] ?? (params['sni'] ?? '');
      grpcMode = params['mode'] ?? 'auto';
      break;
  }

  final alpnStr = params['alpn'] ?? '';
  final alpn = alpnStr.isNotEmpty ? alpnStr.split(',') : <String>[];

  return XrayConfig(
    protocol: 'trojan',
    password: password,
    address: host,
    port: port,
    network: network,
    path: path,
    host: wsHost,
    serviceName: serviceName,
    mode: grpcMode,
    authority: authority,
    security: params['security'] ?? 'tls',
    sni: params['sni'] ?? '',
    fingerprint: params['fp'] ?? '',
    alpn: alpn,
    insecure: params['insecure'] == '1' || params['allowInsecure'] == '1',
    remark: remark,
  );
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

(String, String) _splitHostPort(String hostPort) {
  if (hostPort.startsWith('[')) {
    // IPv6
    final end = hostPort.indexOf(']');
    if (end == -1) throw ArgumentError('Missing ] in IPv6 address');
    final host = hostPort.substring(1, end);
    if (end + 1 >= hostPort.length || hostPort[end + 1] != ':') {
      throw ArgumentError('Missing port after IPv6 address');
    }
    return (host, hostPort.substring(end + 2));
  }
  final lastColon = hostPort.lastIndexOf(':');
  if (lastColon == -1) throw ArgumentError('Missing port in: $hostPort');
  return (hostPort.substring(0, lastColon), hostPort.substring(lastColon + 1));
}
