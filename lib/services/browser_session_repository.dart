import 'dart:convert';

import 'package:sqflite_common_ffi/sqflite_ffi.dart';

import '../models/browser_session.dart';
import 'sensitive_text_redactor.dart';

class BrowserSessionRepository {
  final DatabaseExecutor database;
  final int maxNetworkExchanges;
  final int maxForms;
  final int maxFieldsPerForm;

  const BrowserSessionRepository(
    this.database, {
    this.maxNetworkExchanges = 100,
    this.maxForms = 50,
    this.maxFieldsPerForm = 100,
  });

  static Future<void> createTables(DatabaseExecutor database) async {
    await database.execute('''
      CREATE TABLE IF NOT EXISTS browser_sessions (
        session_id TEXT PRIMARY KEY,
        project_id INTEGER NOT NULL,
        role_id TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL,
        last_active_at TEXT NOT NULL,
        current_url TEXT NOT NULL DEFAULT '',
        dom_sha256 TEXT NOT NULL DEFAULT '',
        forms_json TEXT NOT NULL DEFAULT '[]',
        network_json TEXT NOT NULL DEFAULT '[]',
        evidence_ids_json TEXT NOT NULL DEFAULT '[]',
        FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
      )
    ''');
    await database.execute(
      'CREATE INDEX IF NOT EXISTS idx_browser_sessions_project_status '
      'ON browser_sessions(project_id, status, last_active_at)',
    );
  }

  Future<void> upsert(BrowserSessionSnapshot snapshot) async {
    final forms = snapshot.forms.take(maxForms).map((form) {
      return BrowserFormState(
        selector: _bounded(form.selector, 512),
        method: _bounded(form.method.toUpperCase(), 16),
        action: _sanitizeUrl(form.action),
        fields: form.fields.take(maxFieldsPerForm).map((field) {
          // Field values are intentionally absent from the persistence model.
          return BrowserFormFieldState(
            selector: _bounded(field.selector, 512),
            name: _bounded(field.name, 256),
            type: _bounded(field.type, 64),
            required: field.required,
            disabled: field.disabled,
          );
        }).toList(growable: false),
      ).toMap();
    }).toList(growable: false);

    final network = snapshot.networkExchanges
        .skip(snapshot.networkExchanges.length > maxNetworkExchanges
            ? snapshot.networkExchanges.length - maxNetworkExchanges
            : 0)
        .map((exchange) => BrowserSessionNetworkExchange(
              method: _bounded(exchange.method.toUpperCase(), 16),
              url: _sanitizeUrl(exchange.url),
              statusCode: exchange.statusCode,
            ).toMap())
        .toList(growable: false);

    await database.insert(
      'browser_sessions',
      {
        'session_id': _bounded(snapshot.sessionId, 256),
        'project_id': snapshot.projectId,
        'role_id': _bounded(snapshot.roleId, 256),
        'status': snapshot.status.name,
        'created_at': snapshot.createdAt.toUtc().toIso8601String(),
        'last_active_at': snapshot.lastActiveAt.toUtc().toIso8601String(),
        'current_url': _sanitizeUrl(snapshot.currentUrl),
        'dom_sha256': _bounded(snapshot.domSha256, 128),
        'forms_json': SensitiveTextRedactor.redact(jsonEncode(forms), maxLength: 256 * 1024),
        'network_json': SensitiveTextRedactor.redact(jsonEncode(network), maxLength: 256 * 1024),
        'evidence_ids_json': jsonEncode(snapshot.evidenceArtifactIds.take(100).toList()),
      },
      conflictAlgorithm: ConflictAlgorithm.replace,
    );
  }

  Future<BrowserSessionSnapshot?> get(String sessionId) async {
    final rows = await database.query(
      'browser_sessions',
      where: 'session_id = ?',
      whereArgs: [sessionId],
      limit: 1,
    );
    if (rows.isEmpty) return null;
    return _fromMap(rows.single);
  }

  Future<List<BrowserSessionSnapshot>> activeBefore(DateTime cutoff) async {
    final rows = await database.query(
      'browser_sessions',
      where: 'status IN (?, ?) AND last_active_at < ?',
      whereArgs: [
        BrowserSessionStatus.active.name,
        BrowserSessionStatus.closing.name,
        cutoff.toUtc().toIso8601String(),
      ],
      orderBy: 'last_active_at ASC, session_id ASC',
    );
    return rows.map(_fromMap).toList(growable: false);
  }

  Future<void> markClosed(String sessionId, DateTime closedAt) async {
    await database.update(
      'browser_sessions',
      {
        'status': BrowserSessionStatus.closed.name,
        'last_active_at': closedAt.toUtc().toIso8601String(),
      },
      where: 'session_id = ?',
      whereArgs: [sessionId],
    );
  }

  BrowserSessionSnapshot _fromMap(Map<String, Object?> row) {
    final forms = (jsonDecode(row['forms_json'] as String) as List)
        .map((item) => BrowserFormState.fromMap(Map<String, Object?>.from(item as Map)))
        .toList(growable: false);
    final network = (jsonDecode(row['network_json'] as String) as List)
        .map((item) => BrowserSessionNetworkExchange.fromMap(
              Map<String, Object?>.from(item as Map),
            ))
        .toList(growable: false);
    final evidence = (jsonDecode(row['evidence_ids_json'] as String) as List)
        .whereType<num>()
        .map((value) => value.toInt())
        .toList(growable: false);
    return BrowserSessionSnapshot(
      sessionId: row['session_id'] as String,
      projectId: row['project_id'] as int,
      roleId: row['role_id'] as String,
      status: BrowserSessionStatus.values.firstWhere(
        (value) => value.name == row['status'],
        orElse: () => BrowserSessionStatus.failed,
      ),
      createdAt: DateTime.parse(row['created_at'] as String).toUtc(),
      lastActiveAt: DateTime.parse(row['last_active_at'] as String).toUtc(),
      currentUrl: row['current_url'] as String,
      domSha256: row['dom_sha256'] as String,
      forms: forms,
      networkExchanges: network,
      evidenceArtifactIds: evidence,
    );
  }

  static String _bounded(String value, int maxLength) =>
      SensitiveTextRedactor.redact(value, maxLength: maxLength);

  static String _sanitizeUrl(String value) {
    final redacted = SensitiveTextRedactor.redact(value, maxLength: 4096);
    final uri = Uri.tryParse(redacted);
    if (uri == null || !uri.hasQuery) return redacted;
    final names = uri.queryParametersAll.keys.toList()..sort();
    return uri.replace(
      queryParameters: {for (final name in names) name: '[REDACTED]'},
    ).toString();
  }
}
