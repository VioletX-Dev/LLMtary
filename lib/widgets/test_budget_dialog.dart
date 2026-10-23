import 'package:flutter/material.dart';
import '../models/project.dart';
import '../models/test_budget_mode.dart';

class BudgetConfiguration {
  final TestBudgetMode mode;
  final double limit;
  const BudgetConfiguration(this.mode, this.limit);
}

Future<BudgetConfiguration?> showTestBudgetDialog(
  BuildContext context, {
  Project? project,
  required TestBudgetMode defaultMode,
}) async {
  var mode = project?.budgetMode ?? defaultMode;
  final existingLimit = project?.budgetLimit;
  final controller = TextEditingController(
    text: existingLimit == null
        ? ''
        : existingLimit.toStringAsFixed(existingLimit % 1 == 0 ? 0 : 2),
  );
  String? error;

  final result = await showDialog<BudgetConfiguration>(
    context: context,
    barrierDismissible: project?.hasBudget == true,
    builder: (dialogContext) => StatefulBuilder(
      builder: (context, setState) => AlertDialog(
        backgroundColor: const Color(0xFF1A1F3A),
        title: const Text(
          'TEST BUDGET',
          style: TextStyle(color: Color(0xFF00D4FF)),
        ),
        content: SizedBox(
          width: 420,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text(
                'Budget applies to this test only. Reaching it pauses model-driven testing without deleting progress.',
                style: TextStyle(color: Colors.white70),
              ),
              const SizedBox(height: 16),
              DropdownButtonFormField<TestBudgetMode>(
                initialValue: mode,
                dropdownColor: const Color(0xFF1A1F3A),
                style: const TextStyle(color: Colors.white),
                decoration: const InputDecoration(
                  labelText: 'Budget type',
                  labelStyle: TextStyle(color: Colors.white60),
                ),
                items: const [
                  DropdownMenuItem(
                    value: TestBudgetMode.apiCost,
                    child: Text('API model — estimated USD'),
                  ),
                  DropdownMenuItem(
                    value: TestBudgetMode.localRuntime,
                    child: Text('Local model — runtime'),
                  ),
                ],
                onChanged: (value) {
                  if (value != null) setState(() => mode = value);
                },
              ),
              const SizedBox(height: 14),
              TextField(
                controller: controller,
                keyboardType: const TextInputType.numberWithOptions(
                  decimal: true,
                ),
                style: const TextStyle(color: Colors.white),
                decoration: InputDecoration(
                  labelText: mode == TestBudgetMode.apiCost
                      ? 'Dollar cap (USD)'
                      : 'Runtime limit (minutes)',
                  helperText: mode == TestBudgetMode.apiCost
                      ? 'Cost is estimated from reported token usage and model pricing.'
                      : 'The timer starts with the first local-model test request.',
                  helperStyle: const TextStyle(color: Colors.white54),
                  errorText: error,
                  labelStyle: const TextStyle(color: Colors.white60),
                ),
              ),
            ],
          ),
        ),
        actions: [
          if (project?.hasBudget == true)
            TextButton(
              onPressed: () => Navigator.pop(dialogContext),
              child: const Text('CANCEL'),
            ),
          FilledButton(
            onPressed: () {
              final limit = double.tryParse(controller.text.trim());
              if (limit == null || !limit.isFinite || limit <= 0) {
                setState(() => error = 'Enter a positive amount.');
                return;
              }
              if (project?.budgetMode == TestBudgetMode.apiCost &&
                  mode == TestBudgetMode.apiCost &&
                  limit < project!.budgetSpentUsd) {
                setState(
                  () => error =
                      'Cap cannot be below the already estimated spend of \$${project.budgetSpentUsd.toStringAsFixed(2)}.',
                );
                return;
              }
              Navigator.pop(dialogContext, BudgetConfiguration(mode, limit));
            },
            child: const Text('SAVE BUDGET'),
          ),
        ],
      ),
    ),
  );
  return result;
}
