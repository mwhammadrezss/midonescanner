class IsolatePoolManager {
  final int maxWorkers;

  IsolatePoolManager({
    this.maxWorkers = 4,
  });

  Future<void> initialize() async {
    // future isolate initialization
  }

  Future<void> dispose() async {
    // cleanup
  }
}