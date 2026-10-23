import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/project.dart';
import 'package:llmtary/services/test_budget.dart';

void main() {
  test('project budget configuration and progress survive map round-trip', () {
    final project = Project(
      id: 7,
      name: 'budgeted',
      folderPath: '/tmp/budgeted',
      createdAt: DateTime.utc(2026, 1, 1),
      lastOpenedAt: DateTime.utc(2026, 1, 2),
      budgetMode: TestBudgetMode.apiCost,
      budgetLimit: 25,
      budgetSpentUsd: 4.75,
      budgetStartedAt: DateTime.utc(2026, 1, 2, 3),
    );

    final restored = Project.fromMap(project.toMap());

    expect(restored.budgetMode, TestBudgetMode.apiCost);
    expect(restored.budgetLimit, 25);
    expect(restored.budgetSpentUsd, 4.75);
    expect(restored.budgetStartedAt, DateTime.utc(2026, 1, 2, 3));
    expect(restored.hasBudget, isTrue);
  });

  test('legacy project without budget remains loadable and unconfigured', () {
    final restored = Project.fromMap({
      'id': 8,
      'name': 'legacy',
      'folderPath': '/tmp/legacy',
      'createdAt': DateTime.utc(2026, 1, 1).toIso8601String(),
      'lastOpenedAt': DateTime.utc(2026, 1, 1).toIso8601String(),
    });

    expect(restored.budgetMode, isNull);
    expect(restored.hasBudget, isFalse);
    expect(restored.budgetSpentUsd, 0);
  });

  test('increasing a cap does not reset accumulated usage', () {
    final project = Project(
      id: 9,
      name: 'resume',
      folderPath: '/tmp/resume',
      createdAt: DateTime.utc(2026, 1, 1),
      lastOpenedAt: DateTime.utc(2026, 1, 1),
      budgetMode: TestBudgetMode.apiCost,
      budgetLimit: 10,
      budgetSpentUsd: 9.5,
    );

    final increased = project.copyWith(budgetLimit: 20);
    expect(increased.budgetLimit, 20);
    expect(increased.budgetSpentUsd, 9.5);
  });
}
