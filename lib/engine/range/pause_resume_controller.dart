class PauseResumeController {
  bool _paused = false;

  bool get isPaused => _paused;

  void pause() {
    _paused = true;
  }

  void resume() {
    _paused = false;
  }
}