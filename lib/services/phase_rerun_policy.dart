import '../models/target.dart';
import '../models/vulnerability.dart';

/// Deterministically selects the records included in a normal phase run or an
/// explicit user-requested rerun. Safety, scope, and approval checks still run
/// in the phase executors after this selection step.
class PhaseRerunPolicy {
  const PhaseRerunPolicy._();

  static List<String> reconAddresses(
    Iterable<String> addresses,
    Iterable<Target> existingTargets, {
    required bool forceRerun,
  }) {
    final completed = existingTargets
        .where((target) => target.status == TargetStatus.complete)
        .map((target) => target.address)
        .toSet();
    final selected = <String>[];
    final seen = <String>{};
    for (final address in addresses) {
      if (!seen.add(address)) continue;
      if (!forceRerun && completed.contains(address)) continue;
      selected.add(address);
    }
    return selected;
  }

  static bool preservePriorReconResult(
    Target target, {
    required bool forceRerun,
  }) => forceRerun && target.status == TargetStatus.complete;

  static List<Target> analysisTargets(
    Iterable<Target> targets, {
    required bool forceRerun,
  }) => targets
      .where(
        (target) =>
            target.status == TargetStatus.complete &&
            (forceRerun || !target.analysisComplete),
      )
      .toList();

  static List<Vulnerability> proofFindings(
    Iterable<Vulnerability> findings, {
    required bool forceRerun,
  }) => findings
      .where(
        (finding) =>
            finding.vulnerabilityType != 'AttackChain' &&
            (forceRerun || finding.selected),
      )
      .toList();
}
