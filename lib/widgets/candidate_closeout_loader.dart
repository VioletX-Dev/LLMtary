import 'package:flutter/material.dart';

import '../database/database_helper.dart';
import '../models/candidate_closure.dart';
import '../models/controlled_exploitation.dart';
import '../models/human_validation_work_item.dart';
import '../services/assessment_session_checkpoint.dart';
import 'candidate_closeout_panel.dart';

/// Loads and safely updates the non-secret closeout queue for one project.
class CandidateCloseoutLoader extends StatefulWidget {
  final int projectId;
  final int totalCandidates;

  const CandidateCloseoutLoader({
    super.key,
    required this.projectId,
    required this.totalCandidates,
  });

  @override
  State<CandidateCloseoutLoader> createState() =>
      _CandidateCloseoutLoaderState();
}

class _CandidateCloseoutLoaderState extends State<CandidateCloseoutLoader> {
  List<CandidateClosure> _closures = const [];
  List<ControlledExploitationRecord> _controlledExploitations = const [];
  List<HumanValidationWorkItem> _workItems = const [];
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final closures = await DatabaseHelper.getCandidateClosures(
      widget.projectId,
    );
    final workItems = await DatabaseHelper.getHumanValidationWorkItems(
      widget.projectId,
    );
    final controlledExploitations =
        await DatabaseHelper.getControlledExploitations(widget.projectId);
    if (!mounted) return;
    setState(() {
      _closures = closures;
      _controlledExploitations = controlledExploitations;
      _workItems = workItems;
      _loading = false;
    });
  }

  Future<void> _requeue(CandidateClosure closure) async {
    final updated = closure.copyWith(
      disposition: CandidateDisposition.planned,
      explanation:
          'Eligible for bounded re-test at the next safe candidate boundary.',
      nextAction: 'Resume the assessment closeout queue.',
      updatedAt: DateTime.now().toUtc(),
    );
    await DatabaseHelper.upsertCandidateClosure(updated);
    await _appendCheckpoint(closure.vulnerabilityId);
    await DatabaseHelper.insertSessionEvent(
      projectId: widget.projectId,
      targetId: 0,
      eventType: 'candidate_requeued',
      phase: 'CLOSEOUT',
      metadata: {
        'vulnerability_id': closure.vulnerabilityId,
        'terminal_disposition': updated.disposition.name,
        'reason_code': updated.reasonCode.name,
      },
    );
    await _load();
  }

  Future<void> _recordManualMfa(CandidateClosure closure) async {
    final updated = closure.copyWith(
      disposition: CandidateDisposition.planned,
      explanation:
          'An authorized operator recorded manual MFA completion; no MFA secret was stored.',
      remainingPrerequisites: const [],
      nextAction: 'Resume authenticated claim-specific verification.',
      owner: WorkOwner.operator,
      updatedAt: DateTime.now().toUtc(),
    );
    await DatabaseHelper.upsertCandidateClosure(updated);
    await _appendCheckpoint(closure.vulnerabilityId);
    await DatabaseHelper.insertSessionEvent(
      projectId: widget.projectId,
      targetId: 0,
      eventType: 'candidate_prerequisite_satisfied',
      phase: 'CLOSEOUT',
      metadata: {
        'vulnerability_id': closure.vulnerabilityId,
        'prerequisite': 'manual_mfa_completed',
      },
    );
    await _load();
  }

  Future<void> _addEvidenceReference(
    HumanValidationWorkItem item,
    String reference,
  ) async {
    final updated = item.copyWith(
      evidenceReferences: [...item.evidenceReferences, reference],
      updatedAt: DateTime.now().toUtc(),
    );
    await DatabaseHelper.upsertHumanValidationWorkItem(updated);
    await _load();
  }

  Future<void> _appendCheckpoint(int vulnerabilityId) async {
    final key = AssessmentSessionCheckpoint.settingKey(widget.projectId);
    final encoded = await DatabaseHelper.getSetting(key);
    AssessmentSessionCheckpoint checkpoint;
    try {
      checkpoint = encoded == null
          ? throw const FormatException('missing')
          : AssessmentSessionCheckpoint.decode(encoded);
    } catch (_) {
      checkpoint = AssessmentSessionCheckpoint(
        projectId: widget.projectId,
        phase: AssessmentSessionPhase.execution,
        status: AssessmentSessionStatus.paused,
        pendingVulnerabilityIds: const [],
        updatedAt: DateTime.now().toUtc(),
      );
    }
    final pending = {
      ...checkpoint.pendingVulnerabilityIds,
      vulnerabilityId,
    }.toList()..sort();
    await DatabaseHelper.saveSetting(
      key,
      checkpoint
          .copyWith(
            status: AssessmentSessionStatus.paused,
            pendingVulnerabilityIds: pending,
            updatedAt: DateTime.now().toUtc(),
          )
          .encode(),
    );
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) {
      return const Center(child: CircularProgressIndicator());
    }
    return CandidateCloseoutPanel(
      totalCandidates: widget.totalCandidates,
      closures: _closures,
      controlledExploitations: _controlledExploitations,
      workItems: _workItems,
      onRequeue: _requeue,
      onRecordManualMfa: _recordManualMfa,
      onAddEvidenceReference: _addEvidenceReference,
    );
  }
}
