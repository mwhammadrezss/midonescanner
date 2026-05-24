// lib/engine/grading_engine.dart

String calcGrade(double latMs, int lossPercent, double jitter) {
  if (lossPercent >= 50)                               return 'F';
  if (latMs < 80  && lossPercent == 0 && jitter < 15) return 'A';
  if (latMs < 150 && lossPercent <= 5  && jitter < 30) return 'B';
  if (latMs < 300 && lossPercent <= 15)                return 'C';
  if (latMs < 500 && lossPercent <= 30)                return 'D';
  return 'F';
}
