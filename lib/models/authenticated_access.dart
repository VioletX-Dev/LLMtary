enum AuthenticatedAccessType { usernamePassword, bearerToken, cookies }

/// Operator-supplied access for a web target.
///
/// Instances are intentionally memory-only. Callers must not serialize this
/// model or include its secret-bearing fields in logs or reports.
class AuthenticatedAccess {
  final String targetUrl;
  final AuthenticatedAccessType type;
  final String? username;
  final String? password;
  final String? bearerToken;
  final Map<String, String> cookies;
  final String? csrfHeaderName;
  final String? csrfToken;

  /// Records an MFA step that the operator completed outside LLMtary.
  /// This metadata does not perform or bypass MFA.
  final bool manualMfaCompleted;
  final String? manualMfaNote;
  final DateTime? manualMfaCompletedAt;

  const AuthenticatedAccess({
    required this.targetUrl,
    required this.type,
    this.username,
    this.password,
    this.bearerToken,
    this.cookies = const {},
    this.csrfHeaderName,
    this.csrfToken,
    this.manualMfaCompleted = false,
    this.manualMfaNote,
    this.manualMfaCompletedAt,
  });

  bool get hasManualMfaSession =>
      manualMfaCompleted ||
      (manualMfaNote != null && manualMfaNote!.trim().isNotEmpty) ||
      manualMfaCompletedAt != null;

  /// Values that must be removed before data is written to logs or reports.
  Iterable<String> get secretValues sync* {
    for (final value in <String?>[
      password,
      bearerToken,
      csrfToken,
      ...cookies.values,
    ]) {
      if (value != null && value.isNotEmpty) yield value;
    }
  }

  String redactSecrets(String value) {
    var redacted = value;
    final secrets = secretValues.toSet().toList()
      ..sort((a, b) => b.length.compareTo(a.length));
    for (final secret in secrets) {
      redacted = redacted.replaceAll(secret, '[REDACTED]');
    }
    return redacted;
  }

  /// Returns a command that references execution-only environment variables.
  ///
  /// Secrets are never interpolated into shell source. The caller must pass
  /// [commandEnvironment] to the process runner at execution time.
  String materializeCommand(String command) {
    var materialized = command;
    final replacements = <String, String?>{
      '__LLMTARY_USERNAME__': r'${LLMTARY_USERNAME}',
      '__LLMTARY_PASSWORD__': r'${LLMTARY_PASSWORD}',
      '__LLMTARY_BEARER__': r'${LLMTARY_BEARER}',
      '__LLMTARY_CSRF__': r'${LLMTARY_CSRF}',
    };
    var cookieIndex = 0;
    for (final _ in cookies.values) {
      replacements['__LLMTARY_COOKIE_$cookieIndex'] =
          '\${LLMTARY_COOKIE_$cookieIndex}';
      cookieIndex++;
    }
    for (final entry in replacements.entries) {
      materialized = materialized.replaceAll(entry.key, entry.value!);
    }
    return materialized;
  }

  /// Environment variables used only by the child process executing a
  /// materialized command. Never persist or log this map.
  Map<String, String> get commandEnvironment {
    final environment = <String, String>{};
    if (username != null) environment['LLMTARY_USERNAME'] = username!;
    if (password != null) environment['LLMTARY_PASSWORD'] = password!;
    if (bearerToken != null) environment['LLMTARY_BEARER'] = bearerToken!;
    if (csrfToken != null) environment['LLMTARY_CSRF'] = csrfToken!;
    var cookieIndex = 0;
    for (final value in cookies.values) {
      environment['LLMTARY_COOKIE_$cookieIndex'] = value;
      cookieIndex++;
    }
    return environment;
  }
}
