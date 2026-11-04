import '../models/browser_session.dart';
import 'sensitive_text_redactor.dart';

class BrowserFormStateModeler {
  const BrowserFormStateModeler();

  List<BrowserFormState> fromDom(String dom, {int maxForms = 50, int maxFields = 100}) {
    final forms = <BrowserFormState>[];
    final formPattern = RegExp(
      r'<form\b([^>]*)>([\s\S]*?)<\/form\s*>',
      caseSensitive: false,
    );
    for (final match in formPattern.allMatches(dom).take(maxForms)) {
      final attributes = _attributes(match.group(1) ?? '');
      final body = match.group(2) ?? '';
      final fields = <BrowserFormFieldState>[];
      final fieldPattern = RegExp(
        r'<(?:input|select|textarea)\b([^>]*)>',
        caseSensitive: false,
      );
      for (final fieldMatch in fieldPattern.allMatches(body).take(maxFields)) {
        final field = _attributes(fieldMatch.group(1) ?? '');
        final name = _bounded(field['name'] ?? '', 256);
        final id = _bounded(field['id'] ?? '', 256);
        fields.add(BrowserFormFieldState(
          selector: id.isNotEmpty
              ? '#$id'
              : name.isNotEmpty
                  ? '[name="${name.replaceAll('"', '')}"]'
                  : '',
          name: name,
          type: _bounded(field['type'] ?? 'text', 64).toLowerCase(),
          required: field.containsKey('required'),
          disabled: field.containsKey('disabled'),
        ));
      }
      final id = _bounded(attributes['id'] ?? '', 256);
      final name = _bounded(attributes['name'] ?? '', 256);
      forms.add(BrowserFormState(
        selector: id.isNotEmpty
            ? '#$id'
            : name.isNotEmpty
                ? 'form[name="${name.replaceAll('"', '')}"]'
                : 'form:nth-of-type(${forms.length + 1})',
        method: _bounded(attributes['method'] ?? 'GET', 16).toUpperCase(),
        action: _sanitizeUrl(attributes['action'] ?? ''),
        fields: fields,
      ));
    }
    return List.unmodifiable(forms);
  }

  Map<String, String> _attributes(String source) {
    final result = <String, String>{};
    final pattern = RegExp(
      r'''([:\w-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?''',
      caseSensitive: false,
    );
    for (final match in pattern.allMatches(source)) {
      final key = (match.group(1) ?? '').toLowerCase();
      if (key.isEmpty || key == 'value') continue;
      result[key] = match.group(2) ?? match.group(3) ?? match.group(4) ?? '';
    }
    return result;
  }

  String _bounded(String value, int maxLength) =>
      SensitiveTextRedactor.redact(value, maxLength: maxLength);

  String _sanitizeUrl(String value) {
    final redacted = SensitiveTextRedactor.redact(value, maxLength: 4096);
    final uri = Uri.tryParse(redacted);
    if (uri == null || !uri.hasQuery) return redacted;
    final keys = uri.queryParametersAll.keys.toList()..sort();
    return uri.replace(
      queryParameters: {for (final key in keys) key: '[REDACTED]'},
    ).toString();
  }
}
