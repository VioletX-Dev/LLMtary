import 'package:flutter/material.dart';

import '../models/target.dart';
import '../models/targeted_test_request.dart';

class TargetedTestDialog extends StatefulWidget {
  final List<Target> targets;

  const TargetedTestDialog({super.key, required this.targets});

  @override
  State<TargetedTestDialog> createState() => _TargetedTestDialogState();
}

class _TargetedTestDialogState extends State<TargetedTestDialog> {
  final _formKey = GlobalKey<FormState>();
  final _title = TextEditingController();
  final _objective = TextEditingController();
  final _parameters = TextEditingController();
  final _expected = TextEditingController();
  final _constraints = TextEditingController();
  Target? _target;
  String? _requestError;

  List<Target> get _eligibleTargets => widget.targets
      .where(
        (target) => target.id != null && target.status != TargetStatus.excluded,
      )
      .toList();

  @override
  void initState() {
    super.initState();
    final eligible = _eligibleTargets;
    if (eligible.isNotEmpty) _target = eligible.first;
  }

  @override
  void dispose() {
    _title.dispose();
    _objective.dispose();
    _parameters.dispose();
    _expected.dispose();
    _constraints.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      backgroundColor: const Color(0xFF161929),
      title: const Row(
        children: [
          Icon(Icons.center_focus_strong, color: Color(0xFF00F5FF)),
          SizedBox(width: 10),
          Text(
            'TARGETED SPOT TEST',
            style: TextStyle(color: Color(0xFF00F5FF), fontSize: 17),
          ),
        ],
      ),
      content: SizedBox(
        width: 620,
        child: Form(
          key: _formKey,
          child: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Run one narrowly defined validation without repeating recon or full analysis.',
                  style: TextStyle(color: Colors.white70, fontSize: 12),
                ),
                const SizedBox(height: 12),
                DropdownButtonFormField<Target>(
                  initialValue: _target,
                  dropdownColor: const Color(0xFF1D2135),
                  decoration: _decoration('Existing project target'),
                  items: _eligibleTargets
                      .map(
                        (target) => DropdownMenuItem(
                          value: target,
                          child: Text(
                            target.address,
                            style: const TextStyle(color: Colors.white),
                          ),
                        ),
                      )
                      .toList(),
                  onChanged: (target) => setState(() => _target = target),
                  validator: (target) => target == null
                      ? 'Select an existing project target.'
                      : null,
                ),
                const SizedBox(height: 10),
                _field(
                  _title,
                  'Test title',
                  maxLength: TargetedTestRequest.maxTitleLength,
                ),
                const SizedBox(height: 10),
                _field(
                  _objective,
                  'Test objective',
                  maxLength: TargetedTestRequest.maxObjectiveLength,
                  minLines: 2,
                  required: true,
                ),
                const SizedBox(height: 10),
                _field(
                  _parameters,
                  'Parameters',
                  maxLength: TargetedTestRequest.maxParametersLength,
                  minLines: 2,
                  required: false,
                ),
                const SizedBox(height: 10),
                _field(
                  _expected,
                  'Expected secure result',
                  maxLength: TargetedTestRequest.maxExpectedResultLength,
                  minLines: 2,
                  required: false,
                ),
                const SizedBox(height: 10),
                _field(
                  _constraints,
                  'Additional safety constraints',
                  maxLength: TargetedTestRequest.maxConstraintsLength,
                  minLines: 2,
                  required: false,
                ),
                const SizedBox(height: 12),
                Container(
                  padding: const EdgeInsets.all(10),
                  decoration: BoxDecoration(
                    color: const Color(0xFFFFBB33).withValues(alpha: 0.08),
                    border: Border.all(
                      color: const Color(0xFFFFBB33).withValues(alpha: 0.35),
                    ),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: const Text(
                    'Parameters cannot expand project scope, override exclusions or rules of engagement, or bypass approval and safe-testing limits. Do not enter passwords, tokens, cookies, private keys, or session secrets here; use appliance-local authenticated access.',
                    style: TextStyle(color: Color(0xFFFFD277), fontSize: 11),
                  ),
                ),
                if (_requestError != null) ...[
                  const SizedBox(height: 10),
                  Text(
                    _requestError!,
                    style: const TextStyle(
                      color: Color(0xFFFF6B7A),
                      fontSize: 11,
                    ),
                  ),
                ],
              ],
            ),
          ),
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: const Text('CANCEL'),
        ),
        FilledButton.icon(
          onPressed: _submit,
          icon: const Icon(Icons.play_arrow),
          label: const Text('RUN SPOT TEST'),
        ),
      ],
    );
  }

  InputDecoration _decoration(String label) => InputDecoration(
    labelText: label,
    labelStyle: const TextStyle(color: Colors.white60),
    enabledBorder: const OutlineInputBorder(
      borderSide: BorderSide(color: Color(0xFF343A55)),
    ),
    focusedBorder: const OutlineInputBorder(
      borderSide: BorderSide(color: Color(0xFF00F5FF)),
    ),
    errorBorder: const OutlineInputBorder(
      borderSide: BorderSide(color: Color(0xFFFF4466)),
    ),
  );

  Widget _field(
    TextEditingController controller,
    String label, {
    required int maxLength,
    int minLines = 1,
    bool required = true,
  }) => TextFormField(
    controller: controller,
    minLines: minLines,
    maxLines: minLines + 2,
    maxLength: maxLength,
    style: const TextStyle(color: Colors.white, fontSize: 12),
    decoration: _decoration(label),
    validator: required
        ? (value) => value == null || value.trim().isEmpty ? 'Required' : null
        : null,
  );

  void _submit() {
    setState(() => _requestError = null);
    if (!(_formKey.currentState?.validate() ?? false)) return;
    final target = _target!;
    final request = TargetedTestRequest(
      targetId: target.id!,
      targetAddress: target.address,
      title: _title.text.trim(),
      objective: _objective.text.trim(),
      parameters: _parameters.text.trim(),
      expectedResult: _expected.text.trim(),
      constraints: _constraints.text.trim(),
    );
    final errors = request.validateAgainst(widget.targets);
    if (errors.isNotEmpty) {
      setState(() => _requestError = errors.join('\n'));
      return;
    }
    Navigator.of(context).pop(request);
  }
}
