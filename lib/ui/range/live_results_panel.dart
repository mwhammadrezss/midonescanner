import 'package:flutter/material.dart';

class LiveResultsPanel extends StatelessWidget {
  final List<Map<String, dynamic>> results;

  const LiveResultsPanel({
    super.key,
    required this.results,
  });

  @override
  Widget build(BuildContext context) {
    return Expanded(
      child: ListView.builder(
        itemCount: results.length,
        itemBuilder: (context, index) {
          final item = results[index];

          return Card(
            child: ListTile(
              title: Text(item['ip'].toString()),
              subtitle: Text(
                'Latency: ${item['latency']}ms',
              ),
              trailing: Text(
                item['grade'].toString(),
              ),
            ),
          );
        },
      ),
    );
  }
}