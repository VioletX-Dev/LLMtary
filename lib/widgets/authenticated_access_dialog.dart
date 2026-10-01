import 'package:flutter/material.dart';
import '../models/authenticated_access.dart';

class AuthenticatedAccessDialog extends StatefulWidget {
  const AuthenticatedAccessDialog({super.key});

  @override
  State<AuthenticatedAccessDialog> createState() =>
      _AuthenticatedAccessDialogState();
}

class _AuthenticatedAccessDialogState extends State<AuthenticatedAccessDialog> {
  final _url = TextEditingController();
  final _username = TextEditingController();
  final _secret = TextEditingController();
  final _cookies = TextEditingController();
  final _csrfHeader = TextEditingController();
  final _csrfToken = TextEditingController();
  final _mfaNote = TextEditingController();
  AuthenticatedAccessType _type = AuthenticatedAccessType.usernamePassword;
  bool _manualMfaCompleted = false;

  @override
  void dispose() {
    for (final controller in [
      _url,
      _username,
      _secret,
      _cookies,
      _csrfHeader,
      _csrfToken,
      _mfaNote,
    ]) {
      controller.dispose();
    }
    super.dispose();
  }

  Map<String, String> _parseCookies(String value) {
    final result = <String, String>{};
    for (final part in value.split(';')) {
      final separator = part.indexOf('=');
      if (separator > 0) {
        result[part.substring(0, separator).trim()] = part
            .substring(separator + 1)
            .trim();
      }
    }
    return result;
  }

  void _save() {
    final targetUrl = _url.text.trim();
    if (Uri.tryParse(targetUrl)?.hasAuthority != true) return;
    final secret = _secret.text;
    Navigator.of(context).pop(
      AuthenticatedAccess(
        targetUrl: targetUrl,
        type: _type,
        username: _type == AuthenticatedAccessType.usernamePassword
            ? _username.text.trim()
            : null,
        password: _type == AuthenticatedAccessType.usernamePassword
            ? secret
            : null,
        bearerToken: _type == AuthenticatedAccessType.bearerToken
            ? secret
            : null,
        cookies: _parseCookies(_cookies.text),
        csrfHeaderName: _csrfHeader.text.trim().isEmpty
            ? null
            : _csrfHeader.text.trim(),
        csrfToken: _csrfToken.text.isEmpty ? null : _csrfToken.text,
        manualMfaCompleted: _manualMfaCompleted,
        manualMfaNote: _mfaNote.text.trim().isEmpty
            ? null
            : _mfaNote.text.trim(),
        manualMfaCompletedAt: _manualMfaCompleted
            ? DateTime.now().toUtc()
            : null,
      ),
    );
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
    title: const Text('Authenticated web access'),
    content: SizedBox(
      width: 520,
      child: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Text(
              'Stored in memory for this project session only. MFA must be completed manually; LLMtary does not bypass MFA.',
            ),
            TextField(
              controller: _url,
              decoration: const InputDecoration(labelText: 'Target URL'),
            ),
            DropdownButtonFormField<AuthenticatedAccessType>(
              initialValue: _type,
              decoration: const InputDecoration(
                labelText: 'Authentication type',
              ),
              items: const [
                DropdownMenuItem(
                  value: AuthenticatedAccessType.usernamePassword,
                  child: Text('Username / password'),
                ),
                DropdownMenuItem(
                  value: AuthenticatedAccessType.bearerToken,
                  child: Text('Bearer token'),
                ),
                DropdownMenuItem(
                  value: AuthenticatedAccessType.cookies,
                  child: Text('Cookies / existing session'),
                ),
              ],
              onChanged: (value) => setState(() => _type = value!),
            ),
            if (_type == AuthenticatedAccessType.usernamePassword)
              TextField(
                controller: _username,
                decoration: const InputDecoration(labelText: 'Username'),
              ),
            if (_type != AuthenticatedAccessType.cookies)
              TextField(
                controller: _secret,
                obscureText: true,
                decoration: InputDecoration(
                  labelText: _type == AuthenticatedAccessType.bearerToken
                      ? 'Bearer token'
                      : 'Password',
                ),
              ),
            TextField(
              controller: _cookies,
              obscureText: true,
              decoration: const InputDecoration(
                labelText: 'Cookie header (name=value; name2=value2)',
              ),
            ),
            TextField(
              controller: _csrfHeader,
              decoration: const InputDecoration(
                labelText: 'CSRF header name (optional)',
              ),
            ),
            TextField(
              controller: _csrfToken,
              obscureText: true,
              decoration: const InputDecoration(
                labelText: 'CSRF header value (optional)',
              ),
            ),
            CheckboxListTile(
              contentPadding: EdgeInsets.zero,
              value: _manualMfaCompleted,
              onChanged: (value) =>
                  setState(() => _manualMfaCompleted = value ?? false),
              title: const Text('I completed MFA manually for this session'),
            ),
            TextField(
              controller: _mfaNote,
              decoration: const InputDecoration(
                labelText: 'Manual MFA note (do not enter secrets)',
              ),
            ),
          ],
        ),
      ),
    ),
    actions: [
      TextButton(
        onPressed: () => Navigator.pop(context),
        child: const Text('Cancel'),
      ),
      FilledButton(onPressed: _save, child: const Text('Use for execution')),
    ],
  );
}
