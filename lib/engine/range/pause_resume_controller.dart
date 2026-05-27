// lib/engine/range/pause_resume_controller.dart
// Pause/resume via Completer — real blocking wait

import 'dart:async';

class PauseResumeController {
  bool _paused = false;
  Completer<void>? _pauser;

  bool get isPaused => _paused;

  void pause() {
    if (_paused) return;
    _paused = true;
    _pauser = Completer<void>();
  }

  void resume() {
    if (!_paused) return;
    _paused = false;
    final c = _pauser;
    _pauser = null;
    if (c != null && !c.isCompleted) {
      c.complete();
    }
  }

  /// Awaiting this suspends the caller until resume() is called
  Future<void> waitIfPaused() async {
    if (!_paused) return;
    await _pauser?.future;
  }

  void reset() {
    resume();
    _paused = false;
    _pauser = null;
  }
}
