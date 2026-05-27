class LiveResultStore {
  final List<Map<String, dynamic>> _results = [];

  void add({
    required String ip,
    required double latency,
    required String grade,
  }) {
    _results.add({
      'ip': ip,
      'latency': latency,
      'grade': grade,
    });
  }

  List<Map<String, dynamic>> get results => _results;
}