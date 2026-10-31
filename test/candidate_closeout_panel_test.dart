import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/candidate_closure.dart';
import 'package:llmtary/models/controlled_exploitation.dart';
import 'package:llmtary/widgets/candidate_closeout_panel.dart';

void main() {
  testWidgets('shows explicit supervised extension for exhausted budgets', (
    tester,
  ) async {
    final closure = CandidateClosure(
      vulnerabilityId: 9,
      projectId: 1,
      disposition: CandidateDisposition.safeTestingLimitReached,
      reasonCode: ClosureReasonCode.safeRequestBudgetExhausted,
      explanation: 'Budget exhausted.',
      startedAt: DateTime.utc(2026),
      updatedAt: DateTime.utc(2026),
    );
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: CandidateCloseoutPanel(
            totalCandidates: 1,
            closures: [closure],
            workItems: const [],
            onRequeue: (_) async {},
            onRecordManualMfa: (_) async {},
            onAddEvidenceReference: (item, reference) async {},
          ),
        ),
      ),
    );
    expect(find.text('Extend + requeue'), findsOneWidget);
  });

  testWidgets('shows closeout readiness blocker and safe operator actions', (
    tester,
  ) async {
    final closure = CandidateClosure(
      vulnerabilityId: 8,
      projectId: 1,
      disposition: CandidateDisposition.blockedMfaOperatorAction,
      reasonCode: ClosureReasonCode.manualMfaRequired,
      explanation: 'Manual MFA is required.',
      remainingPrerequisites: const ['operator-completed MFA'],
      nextAction: 'Complete MFA on appliance',
      owner: WorkOwner.operator,
      startedAt: DateTime.utc(2026),
      updatedAt: DateTime.utc(2026),
    );
    final controlled = ControlledExploitationRecord(
      vulnerabilityId: 8,
      projectId: 1,
      eligibility: ExploitationEligibility.notApplicable,
      proofStatus: ControlledProofStatus.blocked,
      proofType: ControlledProofType.none,
      methodId: '',
      accessLevel: 'No safe foothold path.',
      cleanupStatus: CleanupStatus.notRequired,
      startedAt: DateTime.utc(2026),
      updatedAt: DateTime.utc(2026),
    );
    var requeued = false;
    var mfaRecorded = false;
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: CandidateCloseoutPanel(
            totalCandidates: 1,
            closures: [closure],
            controlledExploitations: [controlled],
            workItems: const [],
            onRequeue: (_) async => requeued = true,
            onRecordManualMfa: (_) async => mfaRecorded = true,
            onAddEvidenceReference: (item, reference) async {},
          ),
        ),
      ),
    );
    expect(find.textContaining('100%'), findsOneWidget);
    expect(find.textContaining('blockedMfaOperatorAction'), findsOneWidget);
    expect(
      find.textContaining('Controlled exploitation coverage'),
      findsOneWidget,
    );
    expect(find.textContaining('notApplicable'), findsOneWidget);
    await tester.tap(find.text('Record manual MFA'));
    await tester.pump();
    expect(mfaRecorded, isTrue);
    await tester.tap(find.text('Requeue'));
    await tester.pump();
    expect(requeued, isTrue);
  });
}
