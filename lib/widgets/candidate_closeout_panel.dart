import 'package:flutter/material.dart';

import '../models/candidate_closure.dart';
import '../models/controlled_exploitation.dart';
import '../models/human_validation_work_item.dart';

typedef ClosureAction = Future<void> Function(CandidateClosure closure);
typedef EvidenceReferenceAction =
    Future<void> Function(HumanValidationWorkItem item, String reference);

class CandidateCloseoutPanel extends StatelessWidget {
  final int totalCandidates;
  final List<CandidateClosure> closures;
  final List<ControlledExploitationRecord> controlledExploitations;
  final List<HumanValidationWorkItem> workItems;
  final ClosureAction onRequeue;
  final ClosureAction onRecordManualMfa;
  final EvidenceReferenceAction onAddEvidenceReference;

  const CandidateCloseoutPanel({
    super.key,
    required this.totalCandidates,
    required this.closures,
    this.controlledExploitations = const [],
    required this.workItems,
    required this.onRequeue,
    required this.onRecordManualMfa,
    required this.onAddEvidenceReference,
  });

  @override
  Widget build(BuildContext context) {
    final closed = closures.where((item) => item.isTerminal).length;
    final coverage = totalCandidates == 0
        ? 100
        : ((closed / totalCandidates) * 100).round();
    final unresolved = totalCandidates - closed;
    final completedProofDispositions = controlledExploitations
        .where((item) => item.isComplete)
        .length;
    return Card(
      color: const Color(0xFF1A1F3A),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Assessment Closeout',
              style: TextStyle(
                color: Color(0xFF00F5FF),
                fontSize: 18,
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 8),
            Text(
              'Closure coverage: $closed/$totalCandidates ($coverage%) · '
              '$unresolved without a durable terminal record',
              style: const TextStyle(color: Colors.white70),
            ),
            if (controlledExploitations.isNotEmpty) ...[
              const SizedBox(height: 4),
              Text(
                'Controlled exploitation coverage: '
                '$completedProofDispositions/${controlledExploitations.length}',
                style: const TextStyle(color: Colors.white70),
              ),
            ],
            const SizedBox(height: 12),
            for (final closure in closures)
              _ClosureTile(
                closure: closure,
                onRequeue: onRequeue,
                onRecordManualMfa: onRecordManualMfa,
              ),
            if (controlledExploitations.isNotEmpty) ...[
              const Divider(color: Colors.white24),
              const Text(
                'Controlled exploitation and cleanup',
                style: TextStyle(
                  color: Colors.white,
                  fontWeight: FontWeight.bold,
                ),
              ),
              for (final record in controlledExploitations)
                ListTile(
                  dense: true,
                  title: Text(
                    '${record.eligibility.name} · ${record.proofStatus.name}',
                    style: const TextStyle(color: Colors.white),
                  ),
                  subtitle: Text(
                    '${record.proofType.name} · cleanup=${record.cleanupStatus.name}\n${record.accessLevel}',
                    style: const TextStyle(color: Colors.white60),
                  ),
                ),
            ],
            if (workItems.isNotEmpty) ...[
              const Divider(color: Colors.white24),
              const Text(
                'Human validation queue',
                style: TextStyle(
                  color: Colors.white,
                  fontWeight: FontWeight.bold,
                ),
              ),
              for (final item in workItems)
                ListTile(
                  dense: true,
                  title: Text(
                    item.title,
                    style: const TextStyle(color: Colors.white),
                  ),
                  subtitle: Text(
                    '${item.status.name} · ${item.authorizationRequired}\n${item.safetyNotes}',
                    style: const TextStyle(color: Colors.white60),
                  ),
                  trailing: IconButton(
                    tooltip: 'Add evidence reference',
                    icon: const Icon(
                      Icons.attach_file,
                      color: Color(0xFF00F5FF),
                    ),
                    onPressed: () => _requestEvidenceReference(context, item),
                  ),
                ),
            ],
          ],
        ),
      ),
    );
  }

  Future<void> _requestEvidenceReference(
    BuildContext context,
    HumanValidationWorkItem item,
  ) async {
    final controller = TextEditingController();
    final reference = await showDialog<String>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: const Text('Evidence reference'),
        content: TextField(
          controller: controller,
          decoration: const InputDecoration(
            hintText: 'Local evidence path or approved artifact reference',
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialogContext),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () =>
                Navigator.pop(dialogContext, controller.text.trim()),
            child: const Text('Save reference'),
          ),
        ],
      ),
    );
    controller.dispose();
    if (reference != null && reference.isNotEmpty) {
      await onAddEvidenceReference(item, ClosureSanitizer.text(reference));
    }
  }
}

class _ClosureTile extends StatelessWidget {
  final CandidateClosure closure;
  final ClosureAction onRequeue;
  final ClosureAction onRecordManualMfa;

  const _ClosureTile({
    required this.closure,
    required this.onRequeue,
    required this.onRecordManualMfa,
  });

  @override
  Widget build(BuildContext context) => ListTile(
    dense: true,
    contentPadding: EdgeInsets.zero,
    title: Text(
      '${closure.disposition.name} · ${closure.reasonCode.name}',
      style: const TextStyle(color: Colors.white),
    ),
    subtitle: Text(
      [
        closure.explanation,
        if (closure.remainingPrerequisites.isNotEmpty)
          'Needs: ${closure.remainingPrerequisites.join(', ')}',
        if (closure.nextAction.isNotEmpty)
          'Next: ${closure.nextAction} (${closure.owner.name})',
      ].join('\n'),
      style: const TextStyle(color: Colors.white60),
    ),
    trailing: Wrap(
      spacing: 4,
      children: [
        if (closure.disposition ==
            CandidateDisposition.blockedMfaOperatorAction)
          TextButton(
            onPressed: () => onRecordManualMfa(closure),
            child: const Text('Record manual MFA'),
          ),
        TextButton(
          onPressed: () => onRequeue(closure),
          child: const Text('Requeue'),
        ),
      ],
    ),
  );
}
