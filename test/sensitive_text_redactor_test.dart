import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/services/sensitive_text_redactor.dart';

void main() {
  test(
    'redacts encoded and repeated secret parameters without corrupting text',
    () {
      const input =
          'https://example.test/callback?token%3Dfirst-secret&next=1 '
          'token=second-secret token=third-secret '
          'password%3Amy%20password';

      final redacted = SensitiveTextRedactor.redact(input);

      expect(redacted, isNot(contains('first-secret')));
      expect(redacted, isNot(contains('second-secret')));
      expect(redacted, isNot(contains('third-secret')));
      expect(redacted, isNot(contains('my%20password')));
      expect(redacted, contains('[REDACTED]'));
    },
  );

  test('redacts JSON, authorization, PEM, and bounds multibyte text', () {
    final input =
        '{"authorization":"Bearer abcdef","cookie":"session=abc",'
        '"api_key":"key-value"}\n'
        '-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n'
        '${List.filled(100, 'é').join()}';

    final redacted = SensitiveTextRedactor.redact(input, maxLength: 120);

    expect(redacted, isNot(contains('abcdef')));
    expect(redacted, isNot(contains('session=abc')));
    expect(redacted, isNot(contains('key-value')));
    expect(redacted, isNot(contains('BEGIN PRIVATE KEY')));
    expect(redacted, contains('[REDACTED]'));
    expect(redacted, contains('[truncated]'));
  });
}
