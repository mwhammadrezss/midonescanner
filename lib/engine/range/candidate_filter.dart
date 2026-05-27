// lib/engine/range/candidate_filter.dart
// Real IP candidate filtering after fast TCP probe

import 'fast_probe_engine.dart';
import 'subnet_sampler.dart';

class CandidateFilter {
  /// Accept result: alive, within RTT budget, not timed out
  bool isValid(FastProbeResult result, {double maxRttMs = 800}) {
    return result.alive && !result.timedOut && result.tcpMs <= maxRttMs;
  }

  /// Reject private/reserved IPs
  bool isPublic(String ip) => !SubnetSampler.isPrivate(ip);

  /// Filter a batch: keep valid results, sort ascending by tcpMs
  List<FastProbeResult> filterBatch(
    List<FastProbeResult> results, {
    double maxRttMs = 800,
  }) {
    return results
        .where((r) => isValid(r, maxRttMs: maxRttMs))
        .toList()
      ..sort((a, b) => a.tcpMs.compareTo(b.tcpMs));
  }
}
