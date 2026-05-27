import 'dart:math';

class SubnetSampler {
  final Random _random = Random();

  List<String> sample(String cidr, int count) {
    return List.generate(
      count,
      (index) => '104.16.${_random.nextInt(255)}.${_random.nextInt(255)}',
    );
  }
}