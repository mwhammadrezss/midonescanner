class LiveRanker {
  final Map<String, double> scores = {};

  void update(String ip, double score) {
    scores[ip] = score;
  }

  List<String> topIps() {
    final sorted = scores.entries.toList()
      ..sort((a, b) => b.value.compareTo(a.value));

    return sorted.map((e) => e.key).toList();
  }
}