import 'dart:async';
import 'dart:io';

class FastProbeEngine {
  Future<bool> probe(String ip) async {
    try {
      final socket = await Socket.connect(
        ip,
        443,
        timeout: const Duration(milliseconds: 1200),
      );

      socket.destroy();
      return true;
    } catch (_) {
      return false;
    }
  }
}