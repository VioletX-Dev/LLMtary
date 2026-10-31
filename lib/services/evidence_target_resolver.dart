class EvidenceTargetResolver {
  const EvidenceTargetResolver._();

  static String resolve({
    required String? selectedTarget,
    required Iterable<String> knownTargets,
    required String command,
    required String output,
  }) {
    final selected = selectedTarget?.trim() ?? '';
    if (selected.isNotEmpty && selected.toLowerCase() != 'project') {
      return selected;
    }
    final context = '$command\n$output';
    for (final target in knownTargets) {
      final value = target.trim();
      if (value.isNotEmpty && context.contains(value)) return value;
    }
    final ip = RegExp(
      r'(?<![0-9])(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(?:\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}(?![0-9])',
    ).firstMatch(context)?.group(0);
    if (ip != null) return ip;
    final hostname = RegExp(
      r'(?<![A-Za-z0-9_-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?![A-Za-z0-9_-])',
    ).firstMatch(context)?.group(0);
    return hostname ?? 'unresolved-target';
  }
}
