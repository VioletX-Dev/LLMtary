import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/authenticated_access.dart';
import 'package:llmtary/models/web_session.dart';

void main() {
  group('AuthenticatedAccess', () {
    test('represents username and password access', () {
      const access = AuthenticatedAccess(
        targetUrl: 'https://example.test/app',
        type: AuthenticatedAccessType.usernamePassword,
        username: 'analyst',
        password: 'password-secret',
      );

      expect(access.username, 'analyst');
      expect(access.password, 'password-secret');
      expect(access.hasManualMfaSession, isFalse);
    });

    test('represents bearer, cookie, CSRF, and manual MFA metadata', () {
      final completedAt = DateTime.utc(2026, 9, 30, 12);
      final access = AuthenticatedAccess(
        targetUrl: 'https://example.test/app',
        type: AuthenticatedAccessType.bearerToken,
        bearerToken: 'bearer-secret',
        cookies: const {'session': 'cookie-secret'},
        csrfHeaderName: 'X-CSRF-Token',
        csrfToken: 'csrf-secret',
        manualMfaCompleted: true,
        manualMfaNote: 'Approved on the test device.',
        manualMfaCompletedAt: completedAt,
      );

      expect(access.bearerToken, 'bearer-secret');
      expect(access.cookies, {'session': 'cookie-secret'});
      expect(access.csrfHeaderName, 'X-CSRF-Token');
      expect(access.csrfToken, 'csrf-secret');
      expect(access.hasManualMfaSession, isTrue);
      expect(access.manualMfaCompletedAt, completedAt);
    });

    test('redacts every supplied secret without changing ordinary text', () {
      const access = AuthenticatedAccess(
        targetUrl: 'https://example.test',
        type: AuthenticatedAccessType.usernamePassword,
        username: 'analyst',
        password: 'password-secret',
        bearerToken: 'bearer-secret',
        cookies: {'session': 'cookie-secret'},
        csrfToken: 'csrf-secret',
      );

      final redacted = access.redactSecrets(
        'analyst password-secret bearer-secret cookie-secret csrf-secret safe',
      );

      expect(
        redacted,
        'analyst [REDACTED] [REDACTED] [REDACTED] [REDACTED] safe',
      );
    });

    test('keeps hostile secrets out of shell source', () {
      const access = AuthenticatedAccess(
        targetUrl: 'https://example.test',
        type: AuthenticatedAccessType.bearerToken,
        bearerToken: r'''token'; touch /tmp/should-not-exist; echo 'a''',
      );

      final command = access.materializeCommand(
        'curl -H "Authorization: Bearer __LLMTARY_BEARER__"',
      );

      expect(command, contains(r'${LLMTARY_BEARER}'));
      expect(command, isNot(contains('touch /tmp/should-not-exist')));
      expect(
        access.commandEnvironment['LLMTARY_BEARER'],
        r'''token'; touch /tmp/should-not-exist; echo 'a''',
      );
    });
  });

  group('WebSession.seedFromAccess', () {
    test('injects supplied cookies, bearer token, and CSRF header', () {
      const access = AuthenticatedAccess(
        targetUrl: 'https://example.test/app',
        type: AuthenticatedAccessType.cookies,
        bearerToken: 'bearer-secret',
        cookies: {'session': 'cookie-secret', 'theme': 'dark'},
        csrfHeaderName: 'X-XSRF-TOKEN',
        csrfToken: 'csrf-secret',
        manualMfaCompleted: true,
        manualMfaNote: 'Completed by operator.',
      );
      final session = WebSession(baseUrl: 'https://example.test');

      session.seedFromAccess(access);

      expect(session.cookies, {'session': 'cookie-secret', 'theme': 'dark'});
      expect(session.bearerToken, 'bearer-secret');
      expect(session.csrfTokenName, 'X-XSRF-TOKEN');
      expect(session.csrfTokenValue, 'csrf-secret');
      expect(
        session.curlAuthorizationFlag,
        '-H "Authorization: Bearer bearer-secret"',
      );
      expect(session.toPromptBlock(), contains('MFA is not bypassed'));
    });
  });
}
