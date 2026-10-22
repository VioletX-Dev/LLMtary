import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/services/recon_batch_runner.dart';

void main() {
  group('ReconBatchRunner', () {
    test('checkpoints a completed target before another target finishes', () async {
      final slowTarget = Completer<String?>();
      final checkpoints = <String>[];

      final batch = ReconBatchRunner.run<String?>(
        addresses: const ['10.0.0.1', '10.0.0.2'],
        scan: (address) async {
          if (address == '10.0.0.2') return slowTarget.future;
          return '/results/$address.json';
        },
        onResult: (address, result) async {
          if (result != null) checkpoints.add(address);
        },
        onError: (address, error, stackTrace) async {},
      );

      await Future<void>.delayed(Duration.zero);
      expect(checkpoints, ['10.0.0.1']);

      slowTarget.complete('/results/10.0.0.2.json');
      await batch;
      expect(checkpoints, ['10.0.0.1', '10.0.0.2']);
    });

    test('isolates one target failure and checkpoints successful siblings', () async {
      final checkpoints = <String>[];
      final failures = <String>[];

      await ReconBatchRunner.run<String?>(
        addresses: const ['10.0.0.1', '10.0.0.2'],
        scan: (address) async {
          if (address == '10.0.0.1') throw StateError('recon failed');
          return '/results/$address.json';
        },
        onResult: (address, result) async {
          if (result != null) checkpoints.add(address);
        },
        onError: (address, error, stackTrace) async => failures.add(address),
      );

      expect(failures, ['10.0.0.1']);
      expect(checkpoints, ['10.0.0.2']);
    });

    test('does not misclassify a checkpoint failure as a scan failure', () async {
      var scanFailureCallbacks = 0;

      await expectLater(
        ReconBatchRunner.run<String?>(
          addresses: const ['10.0.0.1'],
          scan: (address) async => '/results/10.0.0.1.json',
          onResult: (address, result) async =>
              throw StateError('database unavailable'),
          onError: (address, error, stackTrace) async =>
              scanFailureCallbacks++,
        ),
        throwsStateError,
      );

      expect(scanFailureCallbacks, 0);
    });
  });
}
