import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/independent_validation.dart';
import 'package:llmtary/services/independent_validation_repository.dart';
import 'package:llmtary/services/independent_validation_policy.dart';
import 'package:llmtary/services/independent_validation_orchestrator.dart';
import 'package:llmtary/services/attack_trace_recorder.dart';
import 'package:llmtary/services/attack_trace_repository.dart';
import 'package:llmtary/services/candidate_closure_repository.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';

class FakeLLMCaller implements LLMCaller {
  final String response;
  final List<String> sequenceResponses;
  int _calls = 0;
  final List<String> messages = [];

  FakeLLMCaller.single(this.response) : sequenceResponses = const [];
  FakeLLMCaller.sequence(this.sequenceResponses) : response = '';

  @override
  Future<String> sendMessage(
    String message, {
    bool useSystemPrompt = true,
  }) async {
    _calls++;
    messages.add(message);
    if (sequenceResponses.isNotEmpty) {
      if (_calls - 1 < sequenceResponses.length) {
        return sequenceResponses[_calls - 1];
      }
      return sequenceResponses.last;
    }
    return response;
  }
}

class _FailingAdvisoryReviewer implements AdvisoryValidationReviewer {
  @override
  Future<void> review(IndependentValidationRecord record) async {
    throw StateError('cloud unavailable');
  }
}

void main() {
  sqfliteFfiInit();

  test(
    'orchestrates proposer and validator with isolated contexts and updates closure on confirmed',
    () async {
      final db = await databaseFactoryFfi.openDatabase(inMemoryDatabasePath);
      addTearDown(db.close);

      // minimal validation run row
      await db.execute(
        'CREATE TABLE validation_runs (id INTEGER PRIMARY KEY, projectId INTEGER NOT NULL, vulnerabilityId INTEGER)',
      );
      await db.insert('validation_runs', {
        'id': 100,
        'projectId': 7,
        'vulnerabilityId': 42,
      });
      await db.execute(
        'CREATE TABLE evidence_artifacts (id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL, vulnerability_id INTEGER NOT NULL)',
      );
      await db.insert('evidence_artifacts', {
        'id': 101,
        'project_id': 7,
        'vulnerability_id': 42,
      });
      await db.insert('evidence_artifacts', {
        'id': 102,
        'project_id': 7,
        'vulnerability_id': 42,
      });

      // create required tables
      await IndependentValidationRepository.createTable(db);
      await CandidateClosureRepository.migrate(db);

      final repository = IndependentValidationRepository(db);
      final closureRepo = CandidateClosureRepository(db);

      // Fake proposer returns confirmed decision with evidence and controls
      final proposerResponse =
          'DECISION:CONFIRMED\nEVIDENCE:[101,102,999]\nCONTROLS:[authenticatedBaseline,unauthorizedComparison]\nCOG: internal reasoning\npassword=super-secret';
      final proposer = FakeLLMCaller.single(proposerResponse);

      // Fake validator returns two successful attempts and confirms
      final validatorResponses = [
        'ATTEMPT: true\nDECISION:INCONCLUSIVE',
        'ATTEMPT: true\nDECISION:CONFIRMED',
      ];
      final validator = FakeLLMCaller.sequence(validatorResponses);

      // Attack trace repo (in-memory)
      await AttackTraceRepository.createTables(db);
      await db.insert('attack_traces', {
        'id': 555,
        'project_id': 7,
        'target_id': 1,
        'vulnerability_id': 42,
        'title': 'Independent validation',
        'status': 'active',
        'summary': '',
        'started_at': DateTime.utc(2026, 11, 4).toIso8601String(),
      });
      final traceRepo = AttackTraceRepository(db);
      final traceRecorder = AttackTraceRecorder(traceRepo);

      final orchestrator = IndependentValidationOrchestrator(
        proposerCaller: proposer,
        validatorCaller: validator,
        repository: repository,
        policy: IndependentValidationPolicy(),
        traceRecorder: traceRecorder,
        closureRepository: closureRepo,
      );

      final result = await orchestrator.run(
        validationRunId: 100,
        projectId: 7,
        vulnerabilityId: 42,
        vulnerabilityClass: VulnerabilityClass.authorization,
        proposerContextId: 'proposal-ctx-1',
        validatorContextId: 'validator-ctx-1',
        proposerPrompt: 'propose the claim',
        validatorPromptTemplate: 'validate: {{claim}} attempt={{attempt}}',
        traceId: 555,
      );

      final stored = await repository.forValidationRun(100);
      expect(result.outcome, stored.outcome);
      expect(stored.outcome, IndependentValidationOutcome.confirmed);
      expect(stored.reproducibilityScore, 1.0);
      expect(stored.directEvidenceArtifactIds, contains(101));
      expect(stored.directEvidenceArtifactIds, isNot(contains(999)));

      final closure = await closureRepo.getClosure(42);
      expect(closure, isNotNull);
      expect(closure!.disposition.name, contains('verified'));
      expect(validator.messages.join('\n'), isNot(contains('super-secret')));
      expect(
        validator.messages.join('\n'),
        isNot(contains('internal reasoning')),
      );

      final resumed = await orchestrator.run(
        validationRunId: 100,
        projectId: 7,
        vulnerabilityId: 42,
        vulnerabilityClass: VulnerabilityClass.authorization,
        proposerContextId: 'proposal-ctx-1',
        validatorContextId: 'validator-ctx-1',
        proposerPrompt: 'must not run again',
        validatorPromptTemplate: 'must not run again',
        traceId: 555,
      );
      expect(resumed.outcome, IndependentValidationOutcome.confirmed);
      expect(proposer._calls, 1);
      expect(validator._calls, 2);
    },
  );

  test('rejects when proposer and validator contexts are equal', () async {
    final db = await databaseFactoryFfi.openDatabase(inMemoryDatabasePath);
    addTearDown(db.close);
    await IndependentValidationRepository.createTable(db);

    final proposer = FakeLLMCaller.single('DECISION:CONFIRMED');
    final validator = FakeLLMCaller.single('ATTEMPT: false');

    final traceRepo = AttackTraceRepository(db);
    final traceRecorder = AttackTraceRecorder(traceRepo);

    final orchestrator = IndependentValidationOrchestrator(
      proposerCaller: proposer,
      validatorCaller: validator,
      repository: IndependentValidationRepository(db),
      policy: IndependentValidationPolicy(),
      traceRecorder: traceRecorder,
      closureRepository: CandidateClosureRepository(db),
    );

    expect(
      () => orchestrator.run(
        validationRunId: 1,
        projectId: 1,
        vulnerabilityId: 2,
        vulnerabilityClass: VulnerabilityClass.other,
        proposerContextId: 'same',
        validatorContextId: 'same',
        proposerPrompt: 'x',
        validatorPromptTemplate: 'x',
        traceId: 1,
      ),
      throwsArgumentError,
    );
  });

  test(
    'rejected or advisory-failed validation does not update candidate closure',
    () async {
      final db = await databaseFactoryFfi.openDatabase(inMemoryDatabasePath);
      addTearDown(db.close);
      await db.execute(
        'CREATE TABLE validation_runs (id INTEGER PRIMARY KEY, projectId INTEGER NOT NULL, vulnerabilityId INTEGER)',
      );
      await db.insert('validation_runs', {
        'id': 101,
        'projectId': 7,
        'vulnerabilityId': 43,
      });
      await IndependentValidationRepository.createTable(db);
      await CandidateClosureRepository.migrate(db);
      await AttackTraceRepository.createTables(db);
      await db.insert('attack_traces', {
        'id': 556,
        'project_id': 7,
        'target_id': 1,
        'vulnerability_id': 43,
        'title': 'Independent validation',
        'status': 'active',
        'summary': '',
        'started_at': DateTime.utc(2026, 11, 4).toIso8601String(),
      });
      final closureRepo = CandidateClosureRepository(db);
      final orchestrator = IndependentValidationOrchestrator(
        proposerCaller: FakeLLMCaller.single('DECISION:REJECTED'),
        validatorCaller: FakeLLMCaller.sequence(const [
          'ATTEMPT:false\nDECISION:REJECTED',
          'ATTEMPT:false\nDECISION:REJECTED',
        ]),
        repository: IndependentValidationRepository(db),
        policy: IndependentValidationPolicy(),
        traceRecorder: AttackTraceRecorder(AttackTraceRepository(db)),
        closureRepository: closureRepo,
        advisoryReviewer: _FailingAdvisoryReviewer(),
      );

      final result = await orchestrator.run(
        validationRunId: 101,
        projectId: 7,
        vulnerabilityId: 43,
        vulnerabilityClass: VulnerabilityClass.other,
        proposerContextId: 'proposal-101',
        validatorContextId: 'validator-101',
        proposerPrompt: 'evaluate',
        validatorPromptTemplate: '{{claim}} {{attempt}}',
        traceId: 556,
      );

      expect(result.outcome, IndependentValidationOutcome.rejected);
      expect(await closureRepo.getClosure(43), isNull);
    },
  );
}
