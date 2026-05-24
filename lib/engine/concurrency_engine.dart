// lib/engine/concurrency_engine.dart
import 'dart:async';

int calcConcurrency(int totalIps) {
  if (totalIps < 100)  return 8;
  if (totalIps < 1000) return 16;
  return 24;
}

class Semaphore {
  int _count;
  final _waiters = <Completer<void>>[];

  Semaphore(this._count);

  Future<void> acquire() async {
    if (_count > 0) {
      _count--;
      return;
    }
    final c = Completer<void>();
    _waiters.add(c);
    await c.future;
  }

  void release() {
    if (_waiters.isNotEmpty) {
      final c = _waiters.removeAt(0);
      c.complete();
    } else {
      _count++;
    }
  }
}
