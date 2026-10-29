import 'package:flutter/material.dart';

class PhaseRerunButton extends StatelessWidget {
  final String phaseLabel;
  final bool enabled;
  final VoidCallback onPressed;

  const PhaseRerunButton({
    super.key,
    required this.phaseLabel,
    required this.onPressed,
    this.enabled = true,
  });

  String get _keyLabel => phaseLabel
      .toLowerCase()
      .replaceAll(RegExp(r'[^a-z0-9]+'), '-')
      .replaceAll(RegExp(r'^-+|-+$'), '');

  @override
  Widget build(BuildContext context) => OutlinedButton.icon(
    key: Key('rerun-$_keyLabel'),
    onPressed: enabled ? onPressed : null,
    icon: const Icon(Icons.replay, size: 15),
    label: Text('RE-RUN $phaseLabel'),
    style: OutlinedButton.styleFrom(
      foregroundColor: const Color(0xFFFFBB33),
      side: BorderSide(
        color: enabled ? const Color(0xFFFFBB33) : Colors.white24,
      ),
      textStyle: const TextStyle(fontSize: 10, fontWeight: FontWeight.bold),
    ),
  );
}
