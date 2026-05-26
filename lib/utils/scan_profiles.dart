// lib/utils/scan_profiles.dart
// p54: scanProfilePresets — Fast / Balanced / Aggressive / Deep preset configs

class ScanProfile {
  final String name;
  final String label;
  final String description;
  final int concurrency;
  final int timeoutMs;
  final int survivalTargetMs;
  final int repeats;

  const ScanProfile({
    required this.name,
    required this.label,
    required this.description,
    required this.concurrency,
    required this.timeoutMs,
    required this.survivalTargetMs,
    required this.repeats,
  });
}

const kScanProfiles = <ScanProfile>[
  ScanProfile(
    name: 'fast',
    label: '⚡ Fast',
    description: 'Quick scan · less accuracy',
    concurrency: 16,
    timeoutMs: 3000,
    survivalTargetMs: 10000,
    repeats: 2,
  ),
  ScanProfile(
    name: 'balanced',
    label: '⚖️ Balanced',
    description: 'Best accuracy/speed ratio',
    concurrency: 8,
    timeoutMs: 5000,
    survivalTargetMs: 20000,
    repeats: 3,
  ),
  ScanProfile(
    name: 'aggressive',
    label: '🔥 Aggressive',
    description: 'High concurrency · more IPs',
    concurrency: 24,
    timeoutMs: 4000,
    survivalTargetMs: 15000,
    repeats: 2,
  ),
  ScanProfile(
    name: 'deep',
    label: '🔬 Deep',
    description: 'Maximum accuracy · slow',
    concurrency: 4,
    timeoutMs: 8000,
    survivalTargetMs: 25000,
    repeats: 5,
  ),
];

ScanProfile getProfile(String name) => kScanProfiles.firstWhere(
      (p) => p.name == name,
      orElse: () => kScanProfiles[1],
    );
