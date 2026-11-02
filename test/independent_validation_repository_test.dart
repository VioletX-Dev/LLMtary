import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/independent_validation.dart';
import 'package:llmtary/services/independent_validation_repository.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';

void main() {
  sqfliteFfiInit();

  test(
    'persists independent validation contexts and deterministic result',
    () async {
      final db = await databaseFactoryFfi.openDatabase(inMemoryDatabasePath);
      addTearDown(db.close);
      await db.execute(
        'CREATE TABLE validation_runs ('
        'id INTEGER PRIMARY KEY, projectId INTEGER NOT NULL, vulnerabilityId INTEGER)',
      );
      await db.insert('validation_runs', {
        'id': 19,
        'projectId': 3,
        'vulnerabilityId': 11,
      });
      await IndependentValidationRepository.createTable(db);
      final repository = IndependentValidationRepository(db);
      final record = IndependentValidationRecord(
        validationRunId: 19,
        projectId: 3,
        vulnerabilityId: 11,
        vulnerabilityClass: VulnerabilityClass.authorization,
        proposerContextId: 'proposal-1',
        validatorContextId: 'validator-1',
        proposerDecision: IndependentValidationDecision.confirmed,
        validatorDecision: IndependentValidationDecision.confirmed,
        outcome: IndependentValidationOutcome.confirmed,
        reproductionAttempts: const [true, true],
        reproducibilityScore: 1,
        directEvidenceArtifactIds: const [41, 42],
        completedControls: const {
          ValidationControl.authenticatedBaseline,
          ValidationControl.unauthorizedComparison,
        },
        missingControls: const {},
        reason: 'Independent decisions agree.',
        createdAt: DateTime.utc(2026, 11, 1, 19),
      );

      final id = await repository.persist(record);
      final loaded = await repository.forValidationRun(19);

      expect(loaded.id, id);
      expect(loaded.proposerContextId, 'proposal-1');
      expect(loaded.validatorContextId, 'validator-1');
      expect(loaded.outcome, IndependentValidationOutcome.confirmed);
      expect(loaded.reproducibilityScore, 1);
      expect(loaded.directEvidenceArtifactIds, [41, 42]);
      expect(
        loaded.completedControls,
        contains(ValidationControl.unauthorizedComparison),
      );
    },
  );
}
