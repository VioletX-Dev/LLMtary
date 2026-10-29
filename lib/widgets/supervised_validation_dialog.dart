import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';

import '../database/database_helper.dart';
import '../models/evidence_artifact.dart';
import '../models/vulnerability.dart';
import '../services/evidence_storage_service.dart';
import '../services/llm_service.dart';
import '../services/supervised_ssh_runner.dart';
import '../services/supervised_validation_planner.dart';
import '../services/supervised_validation_policy.dart';
import '../services/supervised_validation_session.dart';
import 'app_state.dart';

class SupervisedValidationDialog extends StatefulWidget {
  final AppState appState;
  final Vulnerability finding;

  const SupervisedValidationDialog({
    super.key,
    required this.appState,
    required this.finding,
  });

  @override
  State<SupervisedValidationDialog> createState() =>
      _SupervisedValidationDialogState();
}

class _SupervisedValidationDialogState
    extends State<SupervisedValidationDialog> {
  final _engagement = TextEditingController();
  final _operator = TextEditingController();
  final _source = TextEditingController();
  final _destination = TextEditingController();
  final _destinationUser = TextEditingController();
  final _sourceUser = TextEditingController();
  final _keyPath = TextEditingController(
    text: '/home/llmtary/.ssh/llmtary_supervised',
  );
  final _knownHosts = TextEditingController(
    text: '/home/llmtary/.ssh/known_hosts',
  );
  final List<String> _eventSummaries = [];

  SupervisedValidationAuthorization? _authorization;
  SupervisedValidationSession? _session;
  SupervisedValidationProposal? _proposal;

  String _output = '';
  String _status = 'Not started';
  bool _useHop = false;
  bool _observerPresent = false;
  bool _exactApproval = false;
  bool _manualMfaComplete = false;
  bool _evidenceReviewed = false;
  bool _busy = false;
  String? _pendingCleanupActionId;
  List<String> _pendingCleanupCommands = const [];

  Timer? _timeoutMonitor;
  bool _timeoutCheckRunning = false;

  @override
  void initState() {
    super.initState();
    _destination.text = widget.finding.targetAddress;
  }

  @override
  void dispose() {
    _timeoutMonitor?.cancel();
    for (final controller in [
      _engagement,
      _operator,
      _source,
      _destination,
      _destinationUser,
      _sourceUser,
      _keyPath,
      _knownHosts,
    ]) {
      controller.dispose();
    }
    super.dispose();
  }

  Future<void> _start() async {
    if (!_observerPresent) {
      _message('Confirm that the authorized human observer is present.');
      return;
    }
    final project = widget.appState.currentProject;
    if (project?.id == null ||
        widget.finding.id == null ||
        widget.finding.targetId == null) {
      _message('Save the project and finding before starting this mode.');
      return;
    }
    final authorization = SupervisedValidationAuthorization(
      engagementReference: _engagement.text.trim(),
      observingOperator: _operator.text.trim(),
      sourceAddress: _source.text.trim(),
      destinationAddress: _destination.text.trim(),
      expiresAt: DateTime.now()
          .toUtc()
          .add(const Duration(hours: 2))
          .toIso8601String(),
      maximumHopCount: 1,
    );
    setState(() => _busy = true);
    try {
      final session = SupervisedValidationSession(
        authorization: authorization,
        now: () => DateTime.now().toUtc(),
        persistEvent: _persistEvent,
      );
      await session.start(observerPresent: true);
      if (!mounted) return;
      setState(() {
        _authorization = authorization;
        _session = session;
        _status = 'Active — AI plans; observer approves each exact action';
      });
      _startTimeoutMonitor();
    } catch (error) {
      _message(error.toString());
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  void _startTimeoutMonitor() {
    _timeoutMonitor?.cancel();
    _timeoutMonitor = Timer.periodic(const Duration(seconds: 15), (_) async {
      final session = _session;
      if (session == null || _timeoutCheckRunning) return;
      _timeoutCheckRunning = true;
      try {
        final terminated = await session.enforceTimeouts(
          observerPresent: _observerPresent,
        );
        if (terminated) {
          _timeoutMonitor?.cancel();
          if (mounted) {
            setState(
              () => _status =
                  'Terminated: observer presence or session timeout boundary failed closed',
            );
          }
        }
      } finally {
        _timeoutCheckRunning = false;
      }
    });
  }

  Future<void> _propose() async {
    final authorization = _authorization;
    if (authorization == null ||
        _session?.state != SupervisedSessionState.active) {
      _message('Start an active supervised session first.');
      return;
    }
    setState(() {
      _busy = true;
      _proposal = null;
      _exactApproval = false;
      _status = 'AI is selecting one bounded next action…';
    });
    try {
      final llm = LLMService(onPromptResponse: widget.appState.addPromptLog);
      final planner = SupervisedValidationPlanner(
        askModel: (prompt) => llm.sendMessage(
          widget.appState.llmSettings,
          prompt,
          useSystemPrompt: false,
        ),
      );
      final proposal = await planner.proposeNext(
        authorization: authorization,
        priorSanitizedEvents: [
          ..._eventSummaries,
          if (_pendingCleanupActionId != null)
            'Cleanup is mandatory now. Propose exactly one of these predefined cleanup commands and no other action: ${_pendingCleanupCommands.join(', ')}',
        ],
      );
      if (!mounted) return;
      setState(() {
        _proposal = proposal;
        _useHop = proposal.useAuthorizedHop;
        _status = 'Awaiting fresh approval for the exact AI-proposed action';
      });
    } catch (error) {
      _message('The AI proposal was rejected: $error');
      if (mounted) setState(() => _status = 'Proposal blocked');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _execute() async {
    final authorization = _authorization;
    final session = _session;
    final proposal = _proposal;
    if (authorization == null || session == null || proposal == null) return;
    if (!_observerPresent || !_exactApproval) {
      _message('The observer must be present and approve this exact action.');
      return;
    }
    if (_useHop && _sourceUser.text.trim().isEmpty) {
      _message('The authorized source-hop SSH user is required.');
      return;
    }
    if (!_manualMfaComplete) {
      _message(
        'Confirm that any required MFA was completed manually. This mode never automates MFA.',
      );
      return;
    }
    final isCleanupCommand =
        _pendingCleanupActionId != null &&
        _pendingCleanupCommands.contains(proposal.remoteCommand);
    if (_pendingCleanupActionId != null && !isCleanupCommand) {
      _message(
        'Cleanup is pending. The AI may execute only the exact predefined cleanup command.',
      );
      return;
    }
    setState(() {
      _busy = true;
      _status = 'Executing one approved action under observation…';
      _output = '';
    });
    try {
      final result = await session.execute(
        action: proposal.action,
        rationale: proposal.rationale,
        expectedEvidence: proposal.expectedEvidence,
        observerPresent: _observerPresent,
        requestApproval: (_) async => _exactApproval,
        runner: (_) => _runAndCapture(authorization, proposal),
      );
      if (!mounted) return;
      setState(() {
        _evidenceReviewed = false;
        _status = 'Action ${result.status.name}: ${result.reason}';
        _exactApproval = false;
        _proposal = null;
        if (result.status == SupervisedActionStatus.completed &&
            proposal.action.changesState &&
            !isCleanupCommand) {
          _pendingCleanupActionId = proposal.action.actionId;
          _pendingCleanupCommands = proposal.action.cleanupActions;
        }
      });
    } catch (error) {
      _message(error.toString());
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<SupervisedActionOutput> _runAndCapture(
    SupervisedValidationAuthorization authorization,
    SupervisedValidationProposal proposal,
  ) async {
    final evidence = <String>[];
    final before = await _captureEvidence('before', proposal);
    if (before != null) evidence.add(before);
    final duringCapture = Future<String?>.delayed(
      const Duration(milliseconds: 350),
      () => _captureEvidence('during', proposal),
    );
    final result = await SupervisedSshRunner.run(
      authorization: authorization,
      request: SupervisedSshRequest(
        destinationUser: _destinationUser.text.trim(),
        destinationKeyPath: _keyPath.text.trim(),
        knownHostsPath: _knownHosts.text.trim(),
        remoteCommand: proposal.remoteCommand,
        sourceUser: _sourceUser.text.trim(),
        useAuthorizedHop: _useHop,
      ),
    );
    if (mounted) setState(() => _output = result.sanitizedOutput);
    final during = await duringCapture;
    if (during != null) evidence.add(during);
    final after = await _captureEvidence('after', proposal);
    if (after != null) evidence.add(after);
    return SupervisedActionOutput(
      exitCode: result.exitCode,
      sanitizedOutput: result.sanitizedOutput,
      evidenceReferences: evidence,
    );
  }

  Future<String?> _captureEvidence(
    String phase,
    SupervisedValidationProposal proposal,
  ) async {
    try {
      final capture = await EvidenceStorageService.captureDesktop(
        delaySeconds: phase == 'during' ? 0 : 1,
      );
      final artifact = await EvidenceStorageService.importImage(
        project: widget.appState.currentProject!,
        vulnerabilityId: widget.finding.id!,
        sourcePath: capture,
        caption:
            'Human-supervised AI ${proposal.action.actionId} — $phase: ${proposal.expectedEvidence}',
        source: EvidenceSource.captured,
      );
      await DatabaseHelper.insertEvidenceArtifact(artifact);
      final sourceDirectory = File(capture).parent;
      if (await sourceDirectory.exists()) {
        await sourceDirectory.delete(recursive: true);
      }
      return artifact.relativePath;
    } catch (error) {
      _eventSummaries.add(
        '$phase screenshot capture failed: ${error.runtimeType}',
      );
      return null;
    }
  }

  Future<void> _verifyCleanup() async {
    final actionId = _pendingCleanupActionId;
    if (actionId == null) {
      _message('No cleanup verification is pending.');
      return;
    }
    try {
      await _session!.verifyCleanup(actionId: actionId);
      if (!mounted) return;
      setState(() {
        _pendingCleanupActionId = null;
        _pendingCleanupCommands = const [];
        _status = 'Cleanup verified';
      });
    } catch (error) {
      _message(error.toString());
    }
  }

  Future<void> _closeSession() async {
    try {
      await _session?.close(evidenceReviewed: _evidenceReviewed);
      _timeoutMonitor?.cancel();
      if (!mounted) return;
      setState(
        () =>
            _status = 'Closed with cleanup verified and human evidence review',
      );
    } catch (error) {
      _message(error.toString());
    }
  }

  Future<void> _persistEvent(SupervisedValidationEvent event) async {
    final exactAction = switch (event.type) {
      SupervisedEventType.actionProposed ||
      SupervisedEventType.actionApproved ||
      SupervisedEventType.actionRejected ||
      SupervisedEventType.actionBlocked ||
      SupervisedEventType.actionCompleted ||
      SupervisedEventType.actionFailed => _proposal?.remoteCommand ?? '',
      _ => '',
    };
    final metadata = <String, dynamic>{
      'event': event.type.name,
      'event_timestamp': event.timestamp.toIso8601String(),
      'engagement_reference': event.engagementReference,
      'observing_operator': event.observingOperator,
      'source_address': event.sourceAddress,
      'destination_address': event.destinationAddress,
      'vulnerability_id': widget.finding.id,
      'finding': widget.finding.problem,
      'action_id': event.actionId,
      'exact_action': exactAction,
      'rationale': event.rationale,
      'expected_evidence': event.expectedEvidence,
      'detail': event.detail,
      'evidence_references': event.evidenceReferences,
      'disposition': switch (event.type) {
        SupervisedEventType.sessionClosed =>
          'closed with cleanup verified and human evidence review',
        SupervisedEventType.sessionTerminated => 'terminated',
        SupervisedEventType.cleanupVerified => 'cleanup verified',
        _ => '',
      },
    };
    await DatabaseHelper.insertSessionEvent(
      projectId: widget.appState.currentProject!.id!,
      targetId: widget.finding.targetId!,
      eventType: 'supervised_validation_event',
      phase: 'HUMAN-SUPERVISED AI VALIDATION',
      metadata: metadata,
    );
    _eventSummaries.add(
      '${event.timestamp.toIso8601String()} ${event.type.name} ${event.detail}',
    );
  }

  void _message(String value) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(value), backgroundColor: const Color(0xFF7A263A)),
    );
  }

  Widget _field(
    TextEditingController controller,
    String label, {
    bool enabled = true,
  }) => TextField(
    controller: controller,
    enabled: enabled,
    style: const TextStyle(color: Colors.white, fontSize: 13),
    decoration: InputDecoration(
      labelText: label,
      labelStyle: const TextStyle(color: Colors.white60),
      isDense: true,
      border: const OutlineInputBorder(),
    ),
  );

  @override
  Widget build(BuildContext context) {
    final started = _session != null;
    final active = _session?.state == SupervisedSessionState.active;
    final paused = _session?.state == SupervisedSessionState.paused;
    return Dialog(
      backgroundColor: const Color(0xFF171A2B),
      child: SizedBox(
        width: 920,
        height: 780,
        child: Padding(
          padding: const EdgeInsets.all(18),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const Text(
                'HUMAN-SUPERVISED, AI-OPERATED VALIDATION',
                style: TextStyle(
                  color: Color(0xFFB7A7FF),
                  fontWeight: FontWeight.bold,
                  fontSize: 18,
                ),
              ),
              const SizedBox(height: 6),
              const Text(
                'The AI selects and executes one bounded action at a time. The observing human must approve every exact action and may stop the session at any time. Key-based SSH only; passwords, tokens, MFA values, and secrets are never collected or persisted.',
                style: TextStyle(color: Colors.white70, fontSize: 12),
              ),
              const SizedBox(height: 14),
              Wrap(
                spacing: 10,
                runSpacing: 10,
                children: [
                  SizedBox(
                    width: 210,
                    child: _field(
                      _engagement,
                      'Engagement authorization',
                      enabled: !started,
                    ),
                  ),
                  SizedBox(
                    width: 190,
                    child: _field(
                      _operator,
                      'Observing operator',
                      enabled: !started,
                    ),
                  ),
                  SizedBox(
                    width: 170,
                    child: _field(
                      _source,
                      'Authorized source',
                      enabled: !started,
                    ),
                  ),
                  SizedBox(
                    width: 170,
                    child: _field(
                      _destination,
                      'Authorized destination',
                      enabled: !started,
                    ),
                  ),
                  SizedBox(
                    width: 170,
                    child: _field(_destinationUser, 'Destination SSH user'),
                  ),
                  SizedBox(
                    width: 170,
                    child: _field(_sourceUser, 'Source-hop SSH user'),
                  ),
                  SizedBox(
                    width: 330,
                    child: _field(_keyPath, 'Private key path (not contents)'),
                  ),
                  SizedBox(
                    width: 330,
                    child: _field(_knownHosts, 'Pinned known_hosts path'),
                  ),
                ],
              ),
              Row(
                children: [
                  Checkbox(
                    value: _observerPresent,
                    onChanged: _busy
                        ? null
                        : (value) =>
                              setState(() => _observerPresent = value ?? false),
                  ),
                  const Text(
                    'Authorized observer is continuously present',
                    style: TextStyle(color: Colors.white70),
                  ),
                  const SizedBox(width: 16),
                  Checkbox(
                    value: _manualMfaComplete,
                    onChanged: _busy
                        ? null
                        : (value) => setState(
                            () => _manualMfaComplete = value ?? false,
                          ),
                  ),
                  const Text(
                    'Required MFA completed manually',
                    style: TextStyle(color: Colors.white70),
                  ),
                ],
              ),
              Row(
                children: [
                  ElevatedButton(
                    onPressed: _busy || started ? null : _start,
                    child: const Text('START 2-HOUR SESSION'),
                  ),
                  const SizedBox(width: 10),
                  ElevatedButton(
                    onPressed: _busy || !active ? null : _propose,
                    child: const Text('AI: PROPOSE NEXT ACTION'),
                  ),
                  const Spacer(),
                  Text(
                    _status,
                    style: const TextStyle(color: Color(0xFFFFCC66)),
                  ),
                ],
              ),
              const Divider(height: 24),
              if (_proposal != null) ...[
                Text(
                  'AI rationale: ${_proposal!.rationale}',
                  style: const TextStyle(color: Colors.white),
                ),
                Text(
                  'Expected evidence: ${_proposal!.expectedEvidence}',
                  style: const TextStyle(color: Colors.white70),
                ),
                SelectableText(
                  'Exact command: ${_proposal!.remoteCommand}',
                  style: const TextStyle(
                    color: Color(0xFF7FDBCA),
                    fontFamily: 'monospace',
                  ),
                ),
                Text(
                  'Route: ${_proposal!.useAuthorizedHop ? 'one exact authorized hop' : 'direct'}',
                  style: const TextStyle(color: Colors.white70),
                ),
                Row(
                  children: [
                    Checkbox(
                      value: _exactApproval,
                      onChanged: _busy
                          ? null
                          : (value) =>
                                setState(() => _exactApproval = value ?? false),
                    ),
                    const Expanded(
                      child: Text(
                        'I am observing and approve this exact action once. No persistent approval is created.',
                        style: TextStyle(color: Colors.white),
                      ),
                    ),
                    ElevatedButton(
                      onPressed: _busy ? null : _execute,
                      child: const Text('EXECUTE APPROVED ACTION'),
                    ),
                  ],
                ),
              ],
              if (_pendingCleanupActionId != null) ...[
                const Text(
                  'CLEANUP REQUIRED BEFORE CLOSURE',
                  style: TextStyle(
                    color: Color(0xFFFF6B6B),
                    fontWeight: FontWeight.bold,
                  ),
                ),
                SelectableText(
                  _pendingCleanupCommands.join('\n'),
                  style: const TextStyle(
                    color: Colors.white70,
                    fontFamily: 'monospace',
                  ),
                ),
                Align(
                  alignment: Alignment.centerLeft,
                  child: ElevatedButton(
                    onPressed: _busy ? null : _verifyCleanup,
                    child: const Text('VERIFY CLEANUP EVIDENCE'),
                  ),
                ),
              ],
              const SizedBox(height: 8),
              const Text(
                'Sanitized output and evidence',
                style: TextStyle(
                  color: Colors.white70,
                  fontWeight: FontWeight.bold,
                ),
              ),
              Expanded(
                child: Container(
                  padding: const EdgeInsets.all(10),
                  color: const Color(0xFF0D0F1A),
                  child: SingleChildScrollView(
                    child: SelectableText(
                      _output.isEmpty ? 'No action output yet.' : _output,
                      style: const TextStyle(
                        color: Color(0xFFB9F6CA),
                        fontFamily: 'monospace',
                        fontSize: 12,
                      ),
                    ),
                  ),
                ),
              ),
              Row(
                children: [
                  Checkbox(
                    value: _evidenceReviewed,
                    onChanged: _busy || !started
                        ? null
                        : (value) => setState(
                            () => _evidenceReviewed = value ?? false,
                          ),
                  ),
                  const Expanded(
                    child: Text(
                      'The observing human reviewed the sanitized output and before/during/after evidence for client reporting.',
                      style: TextStyle(color: Colors.white70),
                    ),
                  ),
                ],
              ),
              Row(
                mainAxisAlignment: MainAxisAlignment.end,
                children: [
                  TextButton(
                    onPressed: _busy || !active
                        ? null
                        : () => _session!
                              .pause(reason: 'Operator paused the session')
                              .then((_) {
                                if (mounted) {
                                  setState(
                                    () => _status = 'Paused by operator',
                                  );
                                }
                              }),
                    child: const Text('PAUSE'),
                  ),
                  TextButton(
                    onPressed: _busy || !paused || !_observerPresent
                        ? null
                        : () =>
                              _session!.resume(observerPresent: true).then((_) {
                                if (mounted) {
                                  setState(() => _status = 'Active — resumed');
                                }
                              }),
                    child: const Text('RESUME'),
                  ),
                  TextButton(
                    onPressed: _busy || !started ? null : _closeSession,
                    child: const Text('CLOSE WITH VERIFIED CLEANUP'),
                  ),
                  TextButton(
                    onPressed: () async {
                      _timeoutMonitor?.cancel();
                      if (_session != null &&
                          _session!.state != SupervisedSessionState.closed) {
                        await _session!.terminate(
                          reason: 'Operator closed the supervised console',
                        );
                      }
                      if (context.mounted) Navigator.of(context).pop();
                    },
                    child: const Text('TERMINATE / EXIT'),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
}
