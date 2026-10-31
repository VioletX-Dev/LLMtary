import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/services/evidence_target_resolver.dart';

void main() {
  test('resolves the exact known target from command context', () {
    expect(
      EvidenceTargetResolver.resolve(
        selectedTarget: null,
        knownTargets: const ['192.0.2.10', '192.0.2.20'],
        command: 'nmap -sV 192.0.2.20',
        output: '192.0.2.20 is up',
      ),
      '192.0.2.20',
    );
  });

  test('never emits the ambiguous project label', () {
    expect(
      EvidenceTargetResolver.resolve(
        selectedTarget: null,
        knownTargets: const [],
        command: 'nmap -sV target.internal',
        output: '',
      ),
      'target.internal',
    );
    expect(
      EvidenceTargetResolver.resolve(
        selectedTarget: null,
        knownTargets: const [],
        command: 'echo no-target',
        output: '',
      ),
      'unresolved-target',
    );
  });
}
