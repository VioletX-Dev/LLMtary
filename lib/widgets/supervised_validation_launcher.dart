import 'package:flutter/material.dart';

class SupervisedValidationLauncher extends StatelessWidget {
  final int selectedFindingCount;
  final bool selectedFindingSaved;
  final VoidCallback onOpen;

  const SupervisedValidationLauncher({
    super.key,
    required this.selectedFindingCount,
    required this.selectedFindingSaved,
    required this.onOpen,
  });

  @override
  Widget build(BuildContext context) {
    final enabled = selectedFindingCount == 1 && selectedFindingSaved;
    return Tooltip(
      message: enabled
          ? 'Open a human-supervised, AI-operated validation session'
          : 'Select exactly one saved finding first',
      child: ElevatedButton.icon(
        onPressed: enabled ? onOpen : null,
        icon: const Icon(Icons.visibility_outlined, size: 17),
        label: const Text('SUPERVISED AI VALIDATION'),
        style: ElevatedButton.styleFrom(
          backgroundColor: const Color(0xFF6C5CE7),
          foregroundColor: Colors.white,
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 11),
        ),
      ),
    );
  }
}
