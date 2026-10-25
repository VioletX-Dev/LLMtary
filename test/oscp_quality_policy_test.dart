import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  final source = File('lib/services/exploit_executor.dart').readAsStringSync();

  test('assessment prompt requires an OSCP-caliber reasoning workflow', () {
    expect(source, contains('OSCP-CALIBER REASONING WORKFLOW'));
    expect(source, contains('Build a service-specific attack-surface map'));
    expect(source, contains('State one falsifiable hypothesis'));
    expect(source, contains('Choose the single test with the highest information gain'));
    expect(source, contains('Corroborate positive evidence with an independent signal'));
    expect(source, contains('Record exact reproduction steps and remediation evidence'));
  });

  test('execution phases use the same safe vocabulary as the response schema', () {
    expect(source, contains("'SAFE_PROOF',"));
    expect(source, isNot(contains("'EXPLOITATION',\n        ]")));
  });

  test('prompt has no residual exploit-file or sensitive traversal guidance', () {
    expect(
      source,
      isNot(contains('Instead, write exploit scripts to files first')),
    );
    expect(source, isNot(contains('/../../etc/passwd')));
    expect(source, contains('/../../etc/os-release'));
  });

  test('quality gate distinguishes evidence and operational blockers', () {
    expect(source, contains('[blocked_by_safety_policy]'));
    expect(source, contains('[authentication_required]'));
    expect(source, contains('[target_unreachable]'));
    expect(source, contains('[model_loop_no_progress]'));
    expect(source, contains('[inconclusive_evidence]'));
  });

  test('executor injects controlled equivalents for prohibited domains', () {
    expect(
      source,
      contains("import 'safe_capability_mapper.dart';"),
    );
    expect(
      source,
      contains('SafeCapabilityMapper.guidanceFor('),
    );
    expect(
      source,
      contains('safeCapabilityGuidance: safeCapabilityGuidance'),
    );
    expect(
      source,
      contains(r'$safeCapabilityGuidance'),
    );
  });
}
