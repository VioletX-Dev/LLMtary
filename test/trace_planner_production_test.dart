import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/attack_trace.dart';
import 'package:llmtary/services/attack_trace_repository.dart';
import 'package:llmtary/services/trace_planner_facade.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';

Future<(Database, AttackTraceRepository, int)> _fixture() async {
  final db = await databaseFactoryFfi.openDatabase(inMemoryDatabasePath);
  await db.execute('CREATE TABLE projects (id INTEGER PRIMARY KEY)');
  await db.execute('CREATE TABLE targets (id INTEGER PRIMARY KEY, projectId INTEGER NOT NULL)');
  await db.execute(
    'CREATE TABLE vulnerabilities (id INTEGER PRIMARY KEY, projectId INTEGER NOT NULL, targetId INTEGER NOT NULL)',
  );
  await db.insert('projects', {'id': 1});
  await db.insert('targets', {'id': 2, 'projectId': 1});
  await AttackTraceRepository.createTables(db);
  final repository = AttackTraceRepository(db);
  final traceId = await repository.begin(AttackTrace(
    projectId: 1,
    targetId: 2,
    title: 'Production trace',
    startedAt: DateTime.utc(2026, 11, 4, 12),
  ));
  await repository.append(AttackTraceStep(
    traceId: traceId,
    stepKey: 'hypothesis-1',
    kind: AttackTraceStepKind.hypothesis,
    hypothesis: 'Authorization boundary may fail',
    tactic: 'authorization',
    createdAt: DateTime.utc(2026, 11, 4, 12, 1),
  ));
  return (db, repository, traceId);
}

void main() {
  sqfliteFfiInit();

  test('hard-blocks prohibited actions and requires approval plus cleanup', () async {
    final (db, repository, traceId) = await _fixture();
    addTearDown(db.close);
    final planner = TracePlannerFacade(
      repository,
      config: const TracePlannerConfig(
        maxRequests: 4,
        maxTools: 2,
        maxRetries: 1,
        maxRuntime: Duration(hours: 1),
      ),
      now: () => DateTime.utc(2026, 11, 4, 12, 10),
    );

    final prohibited = await planner.evaluateProposal(
      traceId: traceId,
      proposal: const TraceActionProposal(
        actionClass: TraceActionClass.command,
        action: 'mimikatz sekurlsa::logonpasswords',
        hypothesisStepKey: 'hypothesis-1',
      ),
    );
    expect(prohibited.status, TracePlannerDecisionStatus.blocked);

    final missingCleanup = await planner.evaluateProposal(
      traceId: traceId,
      proposal: const TraceActionProposal(
        actionClass: TraceActionClass.stateChanging,
        action: 'create harmless marker',
        hypothesisStepKey: 'hypothesis-1',
      ),
    );
    expect(missingCleanup.status, TracePlannerDecisionStatus.blocked);

    final approval = await planner.evaluateProposal(
      traceId: traceId,
      proposal: const TraceActionProposal(
        actionClass: TraceActionClass.stateChanging,
        action: 'create harmless marker',
        cleanupAction: 'remove harmless marker',
        hypothesisStepKey: 'hypothesis-1',
      ),
    );
    expect(approval.status, TracePlannerDecisionStatus.approvalRequired);
    expect(approval.requiresApproval, isTrue);
  });

  test('enforces request tool retry runtime budgets and resumes pending checkpoint', () async {
    final (db, repository, traceId) = await _fixture();
    addTearDown(db.close);
    var now = DateTime.utc(2026, 11, 4, 12, 5);
    final planner = TracePlannerFacade(
      repository,
      config: const TracePlannerConfig(
        maxRequests: 1,
        maxTools: 1,
        maxRetries: 1,
        maxRuntime: Duration(minutes: 30),
      ),
      now: () => now,
    );

    final planned = await planner.evaluateProposal(
      traceId: traceId,
      proposal: const TraceActionProposal(
        actionClass: TraceActionClass.command,
        action: 'nmap -sV 10.0.0.5',
        hypothesisStepKey: 'hypothesis-1',
      ),
    );
    expect(planned.status, TracePlannerDecisionStatus.planned);

    await planner.pause(traceId);
    final resumed = await planner.resume(traceId);
    expect(resumed.status, TracePlannerCheckpointStatus.running);
    expect(resumed.pendingStepKey, planned.stepKey);

    final exhausted = await planner.evaluateProposal(
      traceId: traceId,
      proposal: const TraceActionProposal(
        actionClass: TraceActionClass.command,
        action: 'curl https://10.0.0.5/',
        hypothesisStepKey: 'hypothesis-1',
      ),
    );
    expect(exhausted.status, TracePlannerDecisionStatus.budgetExhausted);

    now = DateTime.utc(2026, 11, 4, 13);
    final runtime = await planner.evaluateProposal(
      traceId: traceId,
      proposal: const TraceActionProposal(
        actionClass: TraceActionClass.browser,
        action: 'navigate',
        hypothesisStepKey: 'hypothesis-1',
      ),
    );
    expect(runtime.status, TracePlannerDecisionStatus.budgetExhausted);
  });

  test('serializes proof execution and requires verified cleanup for completion', () async {
    final (db, repository, traceId) = await _fixture();
    addTearDown(db.close);
    final planner = TracePlannerFacade(repository);

    expect(await planner.acquireProof(traceId), isTrue);
    expect(await planner.acquireProof(traceId), isFalse);
    planner.releaseProof(traceId);
    expect(await planner.acquireProof(traceId), isTrue);
    planner.releaseProof(traceId);

    expect(
      () => planner.completeStateChange(
        traceId: traceId,
        actionStepKey: 'state-change',
        cleanupVerified: false,
      ),
      throwsStateError,
    );
  });

  test('instrumentation records deterministic lifecycle and summary from persisted data', () async {
    final (db, repository, traceId) = await _fixture();
    addTearDown(db.close);
    final instrumentation = AttackTraceInstrumentation(repository);
    await instrumentation.recordCommand(
      traceId: traceId,
      stepKey: 'command-1',
      parentStepKeys: const ['hypothesis-1'],
      command: 'curl https://target.local/admin',
      output: 'HTTP 403',
      interpretation: 'Boundary enforced',
      adaptation: 'Run unauthorized comparison',
      evidenceArtifactIds: const [8],
      createdAt: DateTime.utc(2026, 11, 4, 12, 2),
    );
    await instrumentation.recordCleanup(
      traceId: traceId,
      stepKey: 'cleanup-1',
      parentStepKeys: const ['command-1'],
      action: 'No state change required',
      verified: true,
      createdAt: DateTime.utc(2026, 11, 4, 12, 3),
    );

    final summary = await const AttackTraceSummaryBuilder().build(repository, traceId);
    expect(summary, contains('Authorization boundary may fail'));
    expect(summary, contains('HTTP 403'));
    expect(summary, contains('cleanup=verified'));
    expect(summary, isNot(contains('confirmed vulnerability')));
  });

  test('traced command runner gates execution and records the validated result', () async {
    final (db, repository, traceId) = await _fixture();
    addTearDown(db.close);
    var calls = 0;
    final runner = TracedCommandRunner(
      planner: TracePlannerFacade(
        repository,
        now: () => DateTime.utc(2026, 11, 4, 12, 4),
      ),
      instrumentation: AttackTraceInstrumentation(repository),
      commandRunner: (command) async {
        calls++;
        return {'exitCode': 0, 'output': 'service open', 'error': ''};
      },
    );
    final result = await runner.execute(
      traceId: traceId,
      proposal: const TraceActionProposal(
        actionClass: TraceActionClass.command,
        action: 'nmap -sV 10.0.0.5',
        hypothesisStepKey: 'hypothesis-1',
      ),
      interpretation: 'Service observed',
      adaptation: 'Validate configuration',
      createdAt: DateTime.utc(2026, 11, 4, 12, 4),
    );
    expect(result['exitCode'], 0);
    expect(calls, 1);
    expect((await repository.graph(traceId)).steps.last.output, 'service open');

    final blocked = await runner.execute(
      traceId: traceId,
      proposal: const TraceActionProposal(
        actionClass: TraceActionClass.command,
        action: 'mimikatz sekurlsa::logonpasswords',
        hypothesisStepKey: 'hypothesis-1',
      ),
      interpretation: '',
      adaptation: '',
      createdAt: DateTime.utc(2026, 11, 4, 12, 5),
    );
    expect(blocked['exitCode'], -1);
    expect(calls, 1);
  });
}
