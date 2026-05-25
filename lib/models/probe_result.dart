// lib/models/probe_result.dart
// Kept for architectural compatibility — not used in main pipeline.
class ProbeResult {
  final bool   success;
  final double latency;
  final int    statusCode;
  final String server;
  final String protocol;
  final bool   tlsValid;
  final int    bytesReceived;
  final bool   frontingPossible;

  const ProbeResult({
    required this.success,
    required this.latency,
    required this.statusCode,
    required this.server,
    required this.protocol,
    required this.tlsValid,
    required this.bytesReceived,
    required this.frontingPossible,
  });
}
