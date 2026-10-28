import 'package:flutter_test/flutter_test.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';
import 'package:llmtary/models/candidate_closure.dart';
import 'package:llmtary/models/controlled_exploitation.dart';
import 'package:llmtary/models/human_validation_work_item.dart';
import 'package:llmtary/services/candidate_closure_repository.dart';

void main() {
  sqfliteFfiInit();
  databaseFactory = databaseFactoryFfi;

  test(
    'v28 closure migration is additive and does not relabel legacy records',
    () async {
      final db = await openDatabase(
        inMemoryDatabasePath,
        singleInstance: false,
      );
      await db.execute('''CREATE TABLE vulnerabilities (
      id INTEGER PRIMARY KEY, projectId INTEGER, status TEXT,
      statusReason TEXT, evidence TEXT
    )''');
      await db.insert('vulnerabilities', {
        'id': 1,
        'projectId': 9,
        'status': 'undetermined',
        'statusReason': '',
        'evidence': 'port reachable',
      });

      await CandidateClosureRepository.migrate(db);

      expect((await db.query('candidate_closures')), isEmpty);
      expect(
        (await db.query('vulnerabilities')).single['status'],
        'undetermined',
      );
      final tables = await db.rawQuery(
        "SELECT name FROM sqlite_master WHERE type='table'",
      );
      final names = tables.map((row) => row['name']).toSet();
      expect(
        names,
        containsAll(['candidate_closures', 'human_validation_work_items']),
      );
      await db.close();
    },
  );

  test(
    'repository round trips closure and human work item without secrets',
    () async {
      final db = await openDatabase(
        inMemoryDatabasePath,
        singleInstance: false,
      );
      await CandidateClosureRepository.migrate(db);
      final repository = CandidateClosureRepository(db);
      final closure = CandidateClosure(
        vulnerabilityId: 4,
        projectId: 2,
        disposition: CandidateDisposition.pendingCustomerClarification,
        reasonCode: ClosureReasonCode.customerClarificationRequired,
        explanation: 'Need owner confirmation token=super-secret-value',
        remainingPrerequisites: const ['asset ownership'],
        nextAction: 'Confirm asset owner',
        owner: WorkOwner.customer,
        startedAt: DateTime.utc(2026),
        updatedAt: DateTime.utc(2026),
      );
      await repository.upsertClosure(closure);
      final loaded = await repository.getClosures(2);
      expect(loaded.single.vulnerabilityId, 4);
      expect(loaded.single.explanation, isNot(contains('super-secret-value')));

      final work = HumanValidationWorkItem(
        id: 'work-4',
        projectId: 2,
        vulnerabilityId: 4,
        title: 'Customer scope decision',
        authorizationRequired: 'Owner approval',
        evidenceRequested: const ['written scope confirmation'],
        safetyNotes: 'No active test',
        owner: WorkOwner.customer,
        status: HumanValidationStatus.waitingCustomer,
        createdAt: DateTime.utc(2026),
        updatedAt: DateTime.utc(2026),
      );
      await repository.upsertWorkItem(work);
      expect((await repository.getWorkItems(2)).single.id, 'work-4');
      await db.close();
    },
  );

  test('repository persists controlled proof and cleanup evidence', () async {
    final db = await openDatabase(inMemoryDatabasePath, singleInstance: false);
    await CandidateClosureRepository.migrate(db);
    final repository = CandidateClosureRepository(db);
    final record = ControlledExploitationRecord(
      vulnerabilityId: 4,
      projectId: 2,
      eligibility: ExploitationEligibility.safeProofEligible,
      proofStatus: ControlledProofStatus.proven,
      proofType: ControlledProofType.protocolBehavior,
      methodId: 'protocol-behavior-proof',
      accessLevel: 'network protocol only',
      evidenceReferences: const ['/evidence/proof.txt'],
      cleanupStatus: CleanupStatus.verified,
      cleanupActions: const ['verify no session remained'],
      cleanupEvidenceReferences: const ['/evidence/cleanup.txt'],
      startedAt: DateTime.utc(2026),
      updatedAt: DateTime.utc(2026),
    );

    await repository.upsertControlledExploitation(record);
    final loaded = await repository.getControlledExploitations(2);

    expect(loaded.single.vulnerabilityId, 4);
    expect(loaded.single.isComplete, isTrue);
    await db.close();
  });
}
