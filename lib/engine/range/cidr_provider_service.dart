class CidrProviderService {
  Future<List<String>> getCloudflareRanges() async {
    return [
      '104.16.0.0/13',
      '172.64.0.0/13',
    ];
  }
}