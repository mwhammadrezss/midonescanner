// lib/utils/validators.dart

bool isValidHttpResponse(String resp) {
  if (!resp.startsWith('HTTP/')) return false;

  if (resp.contains('403 Forbidden')) return false;

  if (resp.length < 40) return false;

  return true;
}
