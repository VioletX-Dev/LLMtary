import 'authenticated_access.dart';

/// Maintains HTTP session state (cookie jar, CSRF token) across iterations
/// when the executor is testing web vulnerabilities.
class WebSession {
  /// Current cookie jar: name → value.
  final Map<String, String> cookies;

  /// Most recently extracted CSRF token name and value.
  String? csrfTokenName;
  String? csrfTokenValue;

  /// Operator-supplied authorization carried into authenticated web requests.
  String? bearerToken;
  String? username;
  String? password;
  bool manualMfaCompleted = false;
  String? manualMfaNote;
  DateTime? manualMfaCompletedAt;

  /// Base URL for the target web application (e.g. "https://example.com").
  final String baseUrl;

  WebSession({required this.baseUrl}) : cookies = {};

  bool get hasCookies => cookies.isNotEmpty;
  bool get hasCsrfToken => csrfTokenName != null && csrfTokenValue != null;
  bool get hasBearerToken => bearerToken != null && bearerToken!.isNotEmpty;
  bool get hasBasicCredentials =>
      username != null &&
      username!.isNotEmpty &&
      password != null &&
      password!.isNotEmpty;

  /// Seed this execution-only session from operator-supplied access.
  void seedFromAccess(AuthenticatedAccess access) {
    cookies.addAll(access.cookies);
    bearerToken = access.bearerToken;
    username = access.username;
    password = access.password;
    csrfTokenName = access.csrfHeaderName;
    csrfTokenValue = access.csrfToken;
    manualMfaCompleted = access.manualMfaCompleted;
    manualMfaNote = access.manualMfaNote;
    manualMfaCompletedAt = access.manualMfaCompletedAt;
  }

  /// Merge cookies from a `Set-Cookie` style string into the jar.
  void addCookie(String name, String value) {
    cookies[name] = value;
  }

  /// Return curl-compatible -b "name=value; name2=value2" flag string.
  String get curlCookieFlag {
    if (cookies.isEmpty) return '';
    final pairs = cookies.entries.map((e) => '${e.key}=${e.value}').join('; ');
    return '-b "$pairs"';
  }

  /// Return curl-compatible -H "X-CSRF-Token: value" flag string if token present.
  String get curlCsrfFlag {
    if (!hasCsrfToken) return '';
    final header = _csrfHeader(csrfTokenName!);
    return '-H "$header: $csrfTokenValue"';
  }

  String get curlAuthorizationFlag =>
      hasBearerToken ? '-H "Authorization: Bearer $bearerToken"' : '';

  String get curlBasicAuthFlag =>
      hasBasicCredentials ? '-u "$username:$password"' : '';

  static String _csrfHeader(String fieldName) {
    final lower = fieldName.toLowerCase();
    if (lower.contains('x-csrf') || lower.contains('x-xsrf')) return fieldName;
    if (lower == 'authenticity_token') return 'X-CSRF-Token';
    if (lower == '__requestverificationtoken')
      return 'RequestVerificationToken';
    return 'X-CSRF-Token';
  }

  /// Prompt block injected into every web-testing iteration. It exposes only
  /// appliance-materialized placeholders, never session values.
  String toPromptBlock() {
    if (!hasCookies &&
        !hasCsrfToken &&
        !hasBearerToken &&
        !hasBasicCredentials &&
        !manualMfaCompleted &&
        (manualMfaNote == null || manualMfaNote!.isEmpty))
      return '';
    final buf = StringBuffer(
      '## WEB SESSION STATE — carry this into every request:\n',
    );
    if (hasCookies) {
      buf.writeln(
        '### Active cookies (include with every authenticated request):',
      );
      var cookieIndex = 0;
      for (final e in cookies.entries) {
        buf.writeln('  - ${e.key} = __LLMTARY_COOKIE_$cookieIndex');
        cookieIndex++;
      }
      final pairs = cookies.keys
          .toList()
          .asMap()
          .entries
          .map((e) => '${e.value}=__LLMTARY_COOKIE_${e.key}')
          .join('; ');
      buf.writeln('  curl flag: -b "$pairs"');
    }
    if (hasCsrfToken) {
      buf.writeln('### CSRF token is present locally but must not be used:');
      buf.writeln(
        '  State-changing POST/PUT/PATCH/DELETE requests are prohibited.',
      );
    }
    if (hasBearerToken) {
      buf.writeln(
        '### Bearer authorization (include with every authenticated request):',
      );
      buf.writeln(
        '  curl flag: -H "Authorization: Bearer '
        '${'__LLMTARY_'
            'BEARER__'}"',
      );
    }
    if (hasBasicCredentials) {
      buf.writeln('### Username/password authorization:');
      buf.writeln(
        '  curl flag: -u "__LLMTARY_USERNAME__:__LLMTARY_PASSWORD__"',
      );
    }
    if (manualMfaCompleted || (manualMfaNote?.isNotEmpty ?? false)) {
      buf.writeln('### Manual MFA session metadata:');
      buf.writeln(
        '  MFA must be completed manually by the operator. MFA is not bypassed.',
      );
      if (manualMfaCompleted) {
        buf.writeln('  Operator marked the MFA step complete.');
      }
      if (manualMfaCompletedAt != null) {
        buf.writeln(
          '  Completed at: ${manualMfaCompletedAt!.toIso8601String()}',
        );
      }
      if (manualMfaNote?.isNotEmpty ?? false) {
        buf.writeln('  Operator note: $manualMfaNote');
      }
    }
    buf.writeln('''
### Rules for session-aware testing:
- Use only GET or HEAD requests to read-only resources
- Include appliance-materialized cookie or authorization placeholders only when authentication is required
- If the session appears expired (redirect to /login), output SESSION_EXPIRED on its own line
- Never output or request cookie values, CSRF values, bearer tokens, passwords, or other session material
''');
    return buf.toString();
  }
}
