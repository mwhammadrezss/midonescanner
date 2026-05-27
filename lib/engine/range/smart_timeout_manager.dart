class SmartTimeoutManager {
  Duration currentTimeout = const Duration(milliseconds: 1200);

  void adjust(double averageRtt) {
    if (averageRtt > 500) {
      currentTimeout = const Duration(milliseconds: 2500);
    } else {
      currentTimeout = const Duration(milliseconds: 1200);
    }
  }
}