// lib/engine/range/isolate_pool_manager.dart
// Isolate pool for CPU-heavy CIDR expansion off the main thread

import 'dart:async';
import 'dart:isolate';
import 'subnet_sampler.dart';

/// Top-level function required by Isolate.spawn — must be top-level
List<String> _expandCidrTask(Map<String, dynamic> args) {
  final cidr = args['cidr'] as String;
  final maxSample = args['maxSample'] as int;
  return SubnetSampler().smart(cidr, maxSample: maxSample);
}

class IsolatePoolManager {
  final int maxWorkers;
  bool _initialized = false;

  IsolatePoolManager({this.maxWorkers = 4});

  Future<void> initialize() async {
    _initialized = true;
  }

  /// Expand CIDR in an isolate to keep the UI thread free.
  /// Falls back to synchronous execution if isolate fails.
  Future<List<String>> expandCidr(String cidr, int maxSample) async {
    if (!_initialized) await initialize();

    try {
      // Use Isolate.run for a clean one-shot isolate (Flutter 3.7+)
      final result = await Isolate.run<List<String>>(
        () => _expandCidrTask({'cidr': cidr, 'maxSample': maxSample}),
      );
      return result;
    } catch (_) {
      // Fallback: synchronous on main isolate
      return SubnetSampler().smart(cidr, maxSample: maxSample);
    }
  }

  Future<void> dispose() async {
    _initialized = false;
  }
}
