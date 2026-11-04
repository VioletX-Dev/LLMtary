class SensitiveTextRedactor {
  const SensitiveTextRedactor._();

  static String redact(String input, {int maxLength = 2 * 1024 * 1024}) {
    var value = input;
    value = value.replaceAllMapped(
      RegExp(
        r'("(?:password|passwd|secret|client[_-]?secret|api[_-]?key|token|access[_-]?token|refresh[_-]?token|authorization|cookie|set-cookie)"\s*:\s*")[^"]*(")',
        caseSensitive: false,
      ),
      (match) => '${match.group(1)}[REDACTED]${match.group(2)}',
    );
    value = value.replaceAll(
      RegExp(
        r'\b(authorization\s*:\s*(?:bearer|basic)\s+)\S+',
        caseSensitive: false,
      ),
      r'$1[REDACTED]',
    );
    value = value.replaceAllMapped(
      RegExp(
        r'\b(password|passwd|secret|client[_-]?secret|api[_-]?key|token|access[_-]?token|refresh[_-]?token|authorization|cookie|set-cookie)(%3[dDaA])[^&\s,;]+',
        caseSensitive: false,
      ),
      (match) => '${match.group(1)}${match.group(2)}%5BREDACTED%5D',
    );
    value = value.replaceAllMapped(
      RegExp(
        r'\b(password|passwd|secret|client[_-]?secret|api[_-]?key|token|access[_-]?token|refresh[_-]?token|cookie|set-cookie)\s*([=:])\s*[^\s,;]+',
        caseSensitive: false,
      ),
      (match) => '${match.group(1)}${match.group(2)}[REDACTED]',
    );
    value = value.replaceAll(
      RegExp(
        r'-----BEGIN [^-]*(?:PRIVATE KEY|CERTIFICATE)-----[\s\S]*?-----END [^-]*(?:PRIVATE KEY|CERTIFICATE)-----',
        caseSensitive: false,
      ),
      '[REDACTED PEM BLOCK]',
    );
    if (value.length <= maxLength) return value;
    return '${value.substring(0, maxLength)}\n...[truncated]';
  }
}
