// lib/engine/watchdog_engine.dart
// p7: watchdogTimeoutGuard — force-kill frozen phases
// p8: phaseDeadlineController — per-phase independent deadlines

import 'dart:async';

/// Watchdog timer that fires a callback if not cancelled within deadline.
class WatchdogGuard {
  Timer? _timer;

  /// Start watchdog with [timeout]. Calls [onTimeout] if not cancelled in time.
  void start(Duration timeout, void Function() onTimeout) {
    _timer?.cancel();
    _timer = Timer(timeout, onTimeout);
  }

  /// Reset the watchdog with a new timeout.
  void reset(Duration timeout, void Function() onTimeout) {
    _timer?.cancel();
    _timer = Timer(timeout, onTimeout);
  }

  /// Cancel the watchdog (task completed in time).
  void cancel() {
    _timer?.cancel();
    _timer = null;
  }

  bool get isActive => _timer?.isActive ?? false;
}

/// p8: Per-phase deadline controller.
/// Each phase gets its own deadline independent of global timeout.
class PhaseDeadlineController {
  final Map<String, WatchdogGuard> _guards = {};

  /// Start deadline for [phase] with [timeout]. Fires [onTimeout] if exceeded.
  void startPhase(String phase, Duration timeout, void Function() onTimeout) {
    _guards[phase]?.cancel();
    final guard = WatchdogGuard();
    _guards[phase] = guard;
    guard.start(timeout, onTimeout);
  }

  /// Mark phase as complete — cancels its watchdog.
  void completePhase(String phase) {
    _guards[phase]?.cancel();
    _guards.remove(phase);
  }

  /// Cancel all active phase watchdogs.
  void cancelAll() {
    for (final guard in _guards.values) {
      guard.cancel();
    }
    _guards.clear();
  }
}

/// Run [fn] with a watchdog. If [fn] doesn't complete within [timeout],
/// completes with [fallback] value.
Future<T> withWatchdog<T>({
  required Future<T> Function() fn,
  required Duration timeout,
  required T fallback,
}) async {
  try {
    return await fn().timeout(timeout, onTimeout: () => fallback);
  } catch (_) {
    return fallback;
  }
}
