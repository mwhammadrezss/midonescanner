import 'dart:async';
import 'worker_pool.dart';
import 'adaptive_concurrency.dart';
import 'fast_probe_engine.dart';
import 'candidate_filter.dart';

enum RangeScanMode { fast, balanced, deep }

class RangeScanEngine {
  final AdaptiveConcurrency adaptiveConcurrency;
  final WorkerPool workerPool;
  final FastProbeEngine probeEngine;
  final CandidateFilter filter;

  RangeScanEngine({
    required this.adaptiveConcurrency,
    required this.workerPool,
    required this.probeEngine,
    required this.filter,
  });

  Stream<String> scan({
    required List<String> cidrs,
    RangeScanMode mode = RangeScanMode.fast,
  }) async* {
    for (final cidr in cidrs) {
      final results = await workerPool.runBatch(
        cidr: cidr,
        concurrency: adaptiveConcurrency.currentConcurrency,
        probe: probeEngine.probe,
      );

      for (final ip in results.where(filter.isValid)) {
        yield ip;
      }

      adaptiveConcurrency.update(results.length);
    }
  }
}