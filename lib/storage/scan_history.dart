// lib/storage/scan_history.dart
// p31: sqliteScanHistory — persistent scan session history (using shared_preferences)
// p32: providerAnalytics — per-country/ISP success rates
// p33: lastGoodIpsCache — quick-load last usable IPs
// p35: rollingFailureTracker — detect aggressive ISP filtering

import 'dart:convert';
import 'package:shared_preferences/shared_preferences.dart';

class ScanHistoryService {
  static final ScanHistoryService _i = ScanHistoryService._();
  factory ScanHistoryService() => _i;
  ScanHistoryService._();

  static const String _historyKey = 'scan_history_v1';
  static const String _lastGoodKey = 'last_good_ips_v1';
  static const String _providerKey = 'provider_analytics_v1';
  static const String _recentResultsKey = 'recent_results_v1';

  // ─── p33: Last Good IPs Cache ─────────────────────────────────────────────

  Future<void> saveGoodIps(List<String> ips) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setStringList(_lastGoodKey, ips.take(50).toList());
  }

  Future<List<String>> loadLastGoodIps() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getStringList(_lastGoodKey) ?? [];
  }

  // ─── p31: Scan Session History ────────────────────────────────────────────

  Future<void> saveScanSession({
    required DateTime time,
    required int totalScanned,
    required int aliveCount,
    required List<String> topIps,
  }) async {
    final prefs = await SharedPreferences.getInstance();
    final existing = prefs.getStringList(_historyKey) ?? [];
    final entry = jsonEncode({
      'time': time.toIso8601String(),
      'total': totalScanned,
      'alive': aliveCount,
      'topIps': topIps.take(5).toList(),
    });
    existing.insert(0, entry);
    await prefs.setStringList(_historyKey, existing.take(20).toList());
  }

  Future<List<Map<String, dynamic>>> loadHistory() async {
    final prefs = await SharedPreferences.getInstance();
    final items = prefs.getStringList(_historyKey) ?? [];
    return items
        .map((s) {
          try {
            return jsonDecode(s) as Map<String, dynamic>;
          } catch (_) {
            return <String, dynamic>{};
          }
        })
        .where((m) => m.isNotEmpty)
        .toList();
  }

  // ─── p32: Provider Analytics ──────────────────────────────────────────────

  Future<void> recordProviderResult(String country, bool success) async {
    if (country.isEmpty) return;
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getString(_providerKey) ?? '{}';
    Map<String, dynamic> map;
    try {
      map = jsonDecode(raw) as Map<String, dynamic>;
    } catch (_) {
      map = {};
    }
    if (!map.containsKey(country)) {
      map[country] = {'success': 0, 'fail': 0};
    }
    if (success) {
      map[country]['success'] = ((map[country]['success'] as int?) ?? 0) + 1;
    } else {
      map[country]['fail'] = ((map[country]['fail'] as int?) ?? 0) + 1;
    }
    await prefs.setString(_providerKey, jsonEncode(map));
  }

  Future<Map<String, dynamic>> loadProviderAnalytics() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getString(_providerKey) ?? '{}';
    try {
      return jsonDecode(raw) as Map<String, dynamic>;
    } catch (_) {
      return {};
    }
  }

  // ─── p35: Rolling Failure Tracker ────────────────────────────────────────

  Future<void> recordRecentResult(bool success) async {
    final prefs = await SharedPreferences.getInstance();
    final recent = prefs.getStringList(_recentResultsKey) ?? [];
    recent.insert(0, success ? '1' : '0');
    await prefs.setStringList(_recentResultsKey, recent.take(100).toList());
  }

  /// Returns true if ISP is currently aggressive (>70% failures in recent results)
  Future<bool> isIspAggressive() async {
    final prefs = await SharedPreferences.getInstance();
    final recent = prefs.getStringList(_recentResultsKey) ?? [];
    if (recent.length < 20) return false;
    final failures = recent.where((r) => r == '0').length;
    return failures / recent.length > 0.7;
  }

  Future<void> clearAll() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_historyKey);
    await prefs.remove(_lastGoodKey);
    await prefs.remove(_providerKey);
    await prefs.remove(_recentResultsKey);
  }
}
