import 'dart:convert';

import '../database/database_helper.dart';

typedef ToolApprovalRead = Future<String?> Function(String key);
typedef ToolApprovalWrite = Future<void> Function(String key, String value);

/// Operator-approved executable names that remain approved across assessments.
///
/// This is consent caching only. Every materialized command must still pass the
/// mandatory runtime safety policy immediately before execution.
class PersistentToolApproval {
  static const settingKey = 'assessment_persistent_tool_approvals_v1';

  static const _blockedBroadTools = <String>{
    'bash',
    'sh',
    'dash',
    'zsh',
    'fish',
    'python',
    'python2',
    'python3',
    'perl',
    'ruby',
    'node',
    'pwsh',
    'powershell',
    'cmd',
    'cmd.exe',
    'source',
    'eval',
    'exec',
    'xargs',
    'find',
    'make',
  };

  final ToolApprovalRead _read;
  final ToolApprovalWrite _write;
  Set<String>? _approvedTools;

  PersistentToolApproval({
    ToolApprovalRead? read,
    ToolApprovalWrite? write,
  })  : _read = read ?? DatabaseHelper.getSetting,
        _write = write ?? DatabaseHelper.saveSetting;

  Future<bool> approveCommand(String command) async {
    final tool = extractTool(command);
    if (tool == null) return false;
    final tools = await _load();
    if (tools.add(tool)) {
      final ordered = tools.toList()..sort();
      await _write(settingKey, jsonEncode(ordered));
    }
    return true;
  }

  Future<bool> isApproved(String command) async {
    final tool = extractTool(command);
    if (tool == null) return false;
    return (await _load()).contains(tool);
  }

  Future<Set<String>> approvedTools() async => Set.unmodifiable(await _load());

  Future<void> removeTool(String tool) async {
    final normalized = _normalizeTool(tool);
    if (normalized == null) return;
    final tools = await _load();
    if (tools.remove(normalized)) {
      final ordered = tools.toList()..sort();
      await _write(settingKey, jsonEncode(ordered));
    }
  }

  Future<Set<String>> _load() async {
    if (_approvedTools != null) return _approvedTools!;
    final loaded = <String>{};
    try {
      final raw = await _read(settingKey);
      if (raw != null && raw.isNotEmpty) {
        final decoded = jsonDecode(raw);
        if (decoded is List) {
          for (final value in decoded) {
            final normalized = _normalizeTool(value.toString());
            if (normalized != null) loaded.add(normalized);
          }
        }
      }
    } catch (_) {
      // Corrupt or unavailable state fails closed.
    }
    _approvedTools = loaded;
    return loaded;
  }

  static String? extractTool(String command) {
    if (_containsShellComposition(command)) return null;
    final tokens = _tokenize(command);
    if (tokens.isEmpty) return null;
    var index = 0;

    while (index < tokens.length && index < 12) {
      while (index < tokens.length && _isAssignment(tokens[index])) {
        index++;
      }
      if (index >= tokens.length) return null;

      final wrapper = _basename(tokens[index]).toLowerCase();
      if (wrapper == 'sudo') {
        index++;
        while (index < tokens.length && tokens[index].startsWith('-')) {
          final option = tokens[index++];
          if ({'-u', '-g', '-h', '-p', '-c', '-t'}.contains(option.toLowerCase()) &&
              index < tokens.length) {
            index++;
          }
        }
        continue;
      }
      if (wrapper == 'env') {
        index++;
        while (index < tokens.length &&
            (tokens[index].startsWith('-') || _isAssignment(tokens[index]))) {
          index++;
        }
        continue;
      }
      if (wrapper == 'timeout') {
        index++;
        while (index < tokens.length && tokens[index].startsWith('-')) {
          index++;
        }
        if (index < tokens.length &&
            RegExp(r'^\d+(?:\.\d+)?[smhd]?$').hasMatch(tokens[index])) {
          index++;
        }
        continue;
      }
      if (wrapper == 'command' || wrapper == 'nohup') {
        index++;
        continue;
      }
      return _normalizeToolToken(tokens[index]);
    }
    return null;
  }

  static String? _normalizeTool(String token) {
    final tool = _basename(token).toLowerCase();
    if (!RegExp(r'^[a-z0-9][a-z0-9._+-]{0,63}$').hasMatch(tool)) return null;
    if (_blockedBroadTools.contains(tool)) return null;
    return tool;
  }

  static String? _normalizeToolToken(String token) {
    if (token.contains('/') || token.contains(r'\')) {
      final normalizedPath = token.replaceAll(r'\', '/');
      const trustedPrefixes = <String>[
        '/bin/',
        '/sbin/',
        '/usr/bin/',
        '/usr/sbin/',
        '/usr/local/bin/',
        '/usr/local/sbin/',
        '/snap/bin/',
      ];
      if (!trustedPrefixes.any(normalizedPath.startsWith)) return null;
    }
    return _normalizeTool(token);
  }

  static String _basename(String token) => token.split(RegExp(r'[/\\]')).last;

  static bool _isAssignment(String token) =>
      RegExp(r'^[A-Za-z_][A-Za-z0-9_]*=').hasMatch(token);

  static List<String> _tokenize(String input) {
    final tokens = <String>[];
    final current = StringBuffer();
    String? quote;
    var escaped = false;

    void flush() {
      if (current.isNotEmpty) {
        tokens.add(current.toString());
        current.clear();
      }
    }

    for (var i = 0; i < input.length; i++) {
      final char = input[i];
      if (escaped) {
        current.write(char);
        escaped = false;
      } else if (char == r'\' && quote != "'") {
        escaped = true;
      } else if (quote != null) {
        if (char == quote) {
          quote = null;
        } else {
          current.write(char);
        }
      } else if (char == '"' || char == "'") {
        quote = char;
      } else if (RegExp(r'\s').hasMatch(char)) {
        flush();
      } else {
        current.write(char);
      }
    }
    if (quote != null) return const [];
    if (escaped) current.write(r'\');
    flush();
    return tokens;
  }

  static bool _containsShellComposition(String input) {
    String? quote;
    var escaped = false;
    for (var i = 0; i < input.length; i++) {
      final char = input[i];
      if (escaped) {
        escaped = false;
        continue;
      }
      if (char == r'\' && quote != "'") {
        escaped = true;
        continue;
      }
      if (quote != null) {
        if (char == quote) quote = null;
        continue;
      }
      if (char == '"' || char == "'") {
        quote = char;
        continue;
      }
      if (char == '|' ||
          char == ';' ||
          char == '&' ||
          char == '\n' ||
          char == '`') {
        return true;
      }
      if (char == r'$' && i + 1 < input.length && input[i + 1] == '(') {
        return true;
      }
    }
    return false;
  }
}
