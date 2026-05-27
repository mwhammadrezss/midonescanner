import 'dart:async';

typedef ProbeCallback = Future<bool> Function(String ip);

class WorkerPool {
  Future<List<String>> runBatch({
    required String cidr,
    required int concurrency,
    required ProbeCallback probe,
  }) async {
    final List<String> alive = [];

    // placeholder IP generation logic
    final ips = List.generate(
      concurrency,
      (index) => '192.168.1.${index + 1}',
    );

    await Future.wait(
      ips.map((ip) async {
        final ok = await probe(ip);
        if (ok) alive.add(ip);
      }),
    );

    return alive;
  }
}