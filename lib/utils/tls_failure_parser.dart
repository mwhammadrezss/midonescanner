// lib/utils/tls_failure_parser.dart
// p18: tlsFailureReasonParser — precise TLS failure classification

/// Detailed TLS failure reason enumeration.
enum TlsFailureReason {
  timeout,
  certRejected,
  connectionReset,
  alert,
  hostUnreachable,
  portClosed,
  blackhole,
  unknown,
}

/// Extension to get human-readable label.
extension TlsFailureReasonLabel on TlsFailureReason {
  String get label {
    switch (this) {
      case TlsFailureReason.timeout:
        return 'Timeout';
      case TlsFailureReason.certRejected:
        return 'Cert Rejected';
      case TlsFailureReason.connectionReset:
        return 'RST';
      case TlsFailureReason.alert:
        return 'TLS Alert';
      case TlsFailureReason.hostUnreachable:
        return 'Unreachable';
      case TlsFailureReason.portClosed:
        return 'Port Closed';
      case TlsFailureReason.blackhole:
        return 'Blackhole';
      case TlsFailureReason.unknown:
        return 'Unknown';
    }
  }
}

/// Parse an exception/error into a TlsFailureReason.
TlsFailureReason parseTlsFailure(Object error) {
  final msg = error.toString().toLowerCase();

  if (msg.contains('timeout') || msg.contains('timed out')) {
    return TlsFailureReason.timeout;
  }
  if (msg.contains('certificate') ||
      msg.contains('handshake') ||
      msg.contains('bad certificate') ||
      msg.contains('cert')) {
    return TlsFailureReason.certRejected;
  }
  if (msg.contains('connection reset') ||
      msg.contains('reset') ||
      msg.contains('connection closed')) {
    return TlsFailureReason.connectionReset;
  }
  if (msg.contains('alert')) {
    return TlsFailureReason.alert;
  }
  if (msg.contains('no route') ||
      msg.contains('unreachable') ||
      msg.contains('network is unreachable')) {
    return TlsFailureReason.hostUnreachable;
  }
  if (msg.contains('connection refused') || msg.contains('refused')) {
    return TlsFailureReason.portClosed;
  }
  return TlsFailureReason.unknown;
}
