import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/services/browser_form_state_modeler.dart';

void main() {
  test('models forms and fields without retaining entered values', () {
    const html = '''
      <form id="login" method="post" action="/sessions?csrf=secret">
        <input name="username" type="email" value="william@example.com" required>
        <input name="password" type="password" value="super-secret">
        <button type="submit">Sign in</button>
      </form>
    ''';

    final forms = const BrowserFormStateModeler().fromDom(html);

    expect(forms, hasLength(1));
    expect(forms.single.selector, '#login');
    expect(forms.single.method, 'POST');
    expect(Uri.decodeComponent(forms.single.action), contains('[REDACTED]'));
    expect(forms.single.fields.map((field) => field.name), ['username', 'password']);
    final serialized = forms.single.toMap().toString();
    expect(serialized, isNot(contains('william@example.com')));
    expect(serialized, isNot(contains('super-secret')));
  });
}
