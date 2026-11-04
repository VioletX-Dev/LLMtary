import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/browser_session.dart';
import 'package:llmtary/services/browser_session_repository.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';

void main() {
  late Database db;

  setUp(() async {
    sqfliteFfiInit();
    db = await databaseFactoryFfi.openDatabase(inMemoryDatabasePath);
    await BrowserSessionRepository.createTables(db);
  });

  tearDown(() => db.close());

  test('persists bounded redacted session state without field values', () async {
    final repository = BrowserSessionRepository(db, maxNetworkExchanges: 2);
    final snapshot = BrowserSessionSnapshot(
      sessionId: 'session-1',
      projectId: 7,
      roleId: 'administrator',
      status: BrowserSessionStatus.active,
      createdAt: DateTime.utc(2026, 11, 4),
      lastActiveAt: DateTime.utc(2026, 11, 4, 0, 1),
      currentUrl: 'https://target.local/account?token=secret-value',
      domSha256: 'abc',
      forms: const [
        BrowserFormState(
          selector: '#login',
          method: 'POST',
          action: '/login',
          fields: [
            BrowserFormFieldState(
              selector: '#password',
              name: 'password',
              type: 'password',
              required: true,
            ),
          ],
        ),
      ],
      networkExchanges: const [
        BrowserSessionNetworkExchange(method: 'GET', url: '/one', statusCode: 200),
        BrowserSessionNetworkExchange(method: 'GET', url: '/two', statusCode: 200),
        BrowserSessionNetworkExchange(
          method: 'POST',
          url: '/three?authorization=Bearer-secret',
          statusCode: 401,
        ),
      ],
      evidenceArtifactIds: const [11, 12],
    );

    await repository.upsert(snapshot);
    final loaded = await repository.get('session-1');

    expect(loaded, isNotNull);
    expect(Uri.decodeComponent(loaded!.currentUrl), contains('[REDACTED]'));
    expect(loaded.currentUrl, isNot(contains('secret-value')));
    expect(loaded.networkExchanges, hasLength(2));
    expect(loaded.networkExchanges.last.url, isNot(contains('Bearer-secret')));
    expect(loaded.forms.single.fields.single.type, 'password');

    final raw = await db.query('browser_sessions');
    final serialized = raw.single.values.join(' ');
    expect(serialized, isNot(contains('secret-value')));
    expect(serialized, isNot(contains('Bearer-secret')));
    expect(serialized, isNot(contains('password":"')));
  });

  test('returns abandoned active sessions and closes them without deletion', () async {
    final repository = BrowserSessionRepository(db);
    await repository.upsert(
      BrowserSessionSnapshot(
        sessionId: 'old',
        projectId: 1,
        roleId: 'user',
        status: BrowserSessionStatus.active,
        createdAt: DateTime.utc(2026, 11, 1),
        lastActiveAt: DateTime.utc(2026, 11, 1),
        currentUrl: 'about:blank',
        domSha256: '',
      ),
    );

    final abandoned = await repository.activeBefore(DateTime.utc(2026, 11, 2));
    expect(abandoned.map((item) => item.sessionId), contains('old'));

    await repository.markClosed('old', DateTime.utc(2026, 11, 4));
    final closed = await repository.get('old');
    expect(closed!.status, BrowserSessionStatus.closed);
    expect(await repository.activeBefore(DateTime.utc(2026, 11, 5)), isEmpty);
  });
}
