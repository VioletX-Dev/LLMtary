import 'package:flutter/material.dart';

import '../models/attack_trace.dart';
import '../models/context_artifact.dart';

class AssessmentContextDialog extends StatelessWidget {
  final List<ContextArtifact> artifacts;
  final List<AttackTraceGraph> traces;

  const AssessmentContextDialog({
    super.key,
    required this.artifacts,
    required this.traces,
  });

  @override
  Widget build(BuildContext context) => Dialog(
    backgroundColor: const Color(0xFF15192D),
    child: ConstrainedBox(
      constraints: const BoxConstraints(maxWidth: 900, maxHeight: 700),
      child: Column(
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(20, 16, 8, 12),
            child: Row(
              children: [
                const Expanded(
                  child: Text(
                    'Assessment Context & Attack Traces',
                    style: TextStyle(
                      color: Colors.white,
                      fontSize: 18,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
                IconButton(
                  tooltip: 'Close',
                  onPressed: () => Navigator.maybePop(context),
                  icon: const Icon(Icons.close, color: Colors.white54),
                ),
              ],
            ),
          ),
          const Divider(height: 1, color: Colors.white12),
          Expanded(
            child: ListView(
              padding: const EdgeInsets.all(16),
              children: [
                _heading('Structured Context (${artifacts.length})'),
                if (artifacts.isEmpty)
                  _empty('No structured context has been ingested.')
                else
                  ...artifacts.map(_artifactTile),
                const SizedBox(height: 20),
                _heading('Graph-Backed Attack Traces (${traces.length})'),
                if (traces.isEmpty)
                  _empty('No attack traces have been recorded.')
                else
                  ...traces.map(_traceTile),
              ],
            ),
          ),
        ],
      ),
    ),
  );

  Widget _heading(String text) => Padding(
    padding: const EdgeInsets.only(bottom: 8),
    child: Text(
      text,
      style: const TextStyle(
        color: Color(0xFF00F5FF),
        fontSize: 14,
        fontWeight: FontWeight.bold,
      ),
    ),
  );

  Widget _artifactTile(ContextArtifact artifact) => Card(
    color: const Color(0xFF202640),
    child: ListTile(
      title: Text(
        artifact.originalFileName,
        style: const TextStyle(color: Colors.white),
      ),
      subtitle: Text(
        '${artifact.type.name} · ${artifact.extractionMethod}\n'
        '${artifact.sizeBytes} bytes · SHA-256 ${artifact.sha256.substring(0, 12)}…',
        style: const TextStyle(color: Colors.white60),
      ),
      isThreeLine: true,
    ),
  );

  Widget _traceTile(AttackTraceGraph graph) => Card(
    color: const Color(0xFF202640),
    child: ExpansionTile(
      collapsedIconColor: Colors.white54,
      iconColor: const Color(0xFF00F5FF),
      title: Text(
        graph.trace.title,
        style: const TextStyle(color: Colors.white),
      ),
      subtitle: Text(
        '${graph.trace.status.name} · ${graph.steps.length} '
        '${graph.steps.length == 1 ? 'step' : 'steps'}',
        style: const TextStyle(color: Colors.white60),
      ),
      children: graph.steps
          .map(
            (step) => ListTile(
              dense: true,
              title: Text(
                '${step.sequence ?? '-'} · ${step.stepKey} · ${step.kind.name}',
                style: const TextStyle(color: Colors.white70),
              ),
              subtitle: step.action.isEmpty
                  ? null
                  : Text(
                      step.action,
                      style: const TextStyle(color: Colors.white54),
                    ),
            ),
          )
          .toList(growable: false),
    ),
  );

  Widget _empty(String text) => Padding(
    padding: const EdgeInsets.symmetric(vertical: 12),
    child: Text(text, style: const TextStyle(color: Colors.white54)),
  );
}
