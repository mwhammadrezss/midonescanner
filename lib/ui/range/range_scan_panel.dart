import 'package:flutter/material.dart';

class RangeScanPanel extends StatefulWidget {
  const RangeScanPanel({super.key});

  @override
  State<RangeScanPanel> createState() => _RangeScanPanelState();
}

class _RangeScanPanelState extends State<RangeScanPanel> {
  double concurrency = 200;
  bool deepMode = false;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Range Scan'),
      ),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: [
            DropdownButton<String>(
              value: 'Cloudflare',
              items: const [
                DropdownMenuItem(
                  value: 'Cloudflare',
                  child: Text('Cloudflare'),
                ),
                DropdownMenuItem(
                  value: 'Fastly',
                  child: Text('Fastly'),
                ),
                DropdownMenuItem(
                  value: 'Google',
                  child: Text('Google'),
                ),
              ],
              onChanged: (_) {},
            ),
            const SizedBox(height: 16),
            Row(
              children: [
                const Text('Concurrency'),
                Expanded(
                  child: Slider(
                    value: concurrency,
                    min: 50,
                    max: 1000,
                    divisions: 19,
                    label: concurrency.toInt().toString(),
                    onChanged: (v) {
                      setState(() {
                        concurrency = v;
                      });
                    },
                  ),
                ),
              ],
            ),
            SwitchListTile(
              title: const Text('Deep Scan'),
              value: deepMode,
              onChanged: (v) {
                setState(() {
                  deepMode = v;
                });
              },
            ),
            const SizedBox(height: 20),
            ElevatedButton(
              onPressed: () {},
              child: const Text('Start Range Scan'),
            ),
          ],
        ),
      ),
    );
  }
}