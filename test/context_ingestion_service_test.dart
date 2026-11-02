import 'dart:convert';

import 'package:archive/archive.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/context_artifact.dart';
import 'package:llmtary/services/context_ingestion_service.dart';

void main() {
  test('parses context asynchronously off the caller isolate', () async {
    final result = await const ContextIngestionService().ingestBytesAsync(
      projectId: 9,
      fileName: 'architecture.md',
      bytes: utf8.encode('# Architecture'),
      ingestedAt: DateTime.utc(2026, 11, 1, 19, 15),
    );

    expect(result.artifact.type, ContextArtifactType.architectureDocument);
  });

  test('redacts secret values before normalized context is persisted', () {
    final result = ContextIngestionService().ingestBytes(
      projectId: 9,
      fileName: 'architecture.json',
      bytes: utf8.encode(jsonEncode({
        'apiKey': 'secret-value-123',
        'description': 'Safe architecture note',
      })),
      ingestedAt: DateTime.utc(2026, 11, 1, 19, 5),
    );

    expect(result.normalizedText, isNot(contains('secret-value-123')));
    expect(result.normalizedText, contains('[REDACTED]'));
  });

  test('rejects source archives that exceed expanded byte limits', () {
    final archive = Archive()
      ..addFile(ArchiveFile.bytes('large.txt', utf8.encode('1234')));
    final bytes = ZipEncoder().encode(archive);

    expect(
      () => ContextIngestionService(maxExpandedArchiveBytes: 3).ingestBytes(
        projectId: 9,
        fileName: 'large.zip',
        bytes: bytes,
        ingestedAt: DateTime.utc(2026, 11, 1, 19),
      ),
      throwsFormatException,
    );
  });

  test('classifies architecture documents and preserves normalized text', () {
    const document = '# Architecture\n\nGateway -> API -> Database\n';
    final result = ContextIngestionService().ingestBytes(
      projectId: 9,
      fileName: 'system-architecture.md',
      bytes: utf8.encode(document),
      ingestedAt: DateTime.utc(2026, 11, 1, 18, 45),
    );

    expect(result.artifact.type, ContextArtifactType.architectureDocument);
    expect(result.artifact.extractionMethod, 'architecture-text-deterministic');
    expect(result.normalizedText, document);
  });

  test('normalizes prior report findings with provenance', () {
    final result = ContextIngestionService().ingestBytes(
      projectId: 9,
      fileName: 'prior-report.json',
      bytes: utf8.encode(
        jsonEncode({
          'findings': [
            {
              'title': 'Missing authorization check',
              'severity': 'high',
              'status': 'open',
              'evidence': 'Peer record returned HTTP 200',
              'remediation': 'Enforce object ownership.',
            },
          ],
        }),
      ),
      ingestedAt: DateTime.utc(2026, 11, 1, 18, 40),
    );

    expect(result.artifact.type, ContextArtifactType.priorReport);
    expect(result.artifact.extractionMethod, 'prior-report-json-deterministic');
    expect(result.priorFindings.single.title, 'Missing authorization check');
    expect(result.priorFindings.single.severity, 'HIGH');
    expect(result.priorFindings.single.status, 'open');
    expect(result.provenance.sourceDigest, result.artifact.sha256);
  });

  test(
    'extracts production and development dependencies from package manifests',
    () {
      final result = ContextIngestionService().ingestBytes(
        projectId: 9,
        fileName: 'package.json',
        bytes: utf8.encode(
          jsonEncode({
            'dependencies': {'express': '^5.0.0'},
            'devDependencies': {'vitest': '^3.0.0'},
          }),
        ),
        ingestedAt: DateTime.utc(2026, 11, 1, 18, 35),
      );

      expect(result.artifact.type, ContextArtifactType.dependencyManifest);
      expect(
        result.artifact.extractionMethod,
        'npm-package-json-deterministic',
      );
      expect(result.dependencies, hasLength(2));
      expect(
        result.dependencies.first,
        isA<DependencyContext>()
            .having((item) => item.name, 'name', 'express')
            .having((item) => item.ecosystem, 'ecosystem', 'npm')
            .having((item) => item.developmentOnly, 'developmentOnly', isFalse),
      );
      expect(result.dependencies.last.name, 'vitest');
      expect(result.dependencies.last.developmentOnly, isTrue);
    },
  );

  test('deterministically extracts OpenAPI YAML endpoints', () {
    const source = '''
openapi: 3.0.3
info:
  title: Inventory API
  version: 1.0.0
paths:
  /items/{id}:
    parameters:
      - name: id
        in: path
    delete:
      operationId: deleteItem
      security:
        - bearerAuth: []
''';

    final result = ContextIngestionService().ingestBytes(
      projectId: 9,
      fileName: 'inventory.openapi.yaml',
      bytes: utf8.encode(source),
      ingestedAt: DateTime.utc(2026, 11, 1, 18, 30),
    );

    expect(result.artifact.type, ContextArtifactType.apiSpecification);
    expect(result.artifact.extractionMethod, 'openapi-yaml-deterministic');
    expect(result.apiEndpoints.single.method, 'DELETE');
    expect(result.apiEndpoints.single.path, '/items/{id}');
    expect(result.apiEndpoints.single.parameterNames, ['id']);
    expect(result.apiEndpoints.single.securitySchemes, ['bearerAuth']);
  });

  test('deterministically extracts OpenAPI endpoints with provenance', () {
    const source = {
      'openapi': '3.0.3',
      'info': {'title': 'Billing API', 'version': '1.2.0'},
      'servers': [
        {'url': 'https://billing.example.test/api'},
      ],
      'paths': {
        '/accounts/{id}': {
          'get': {
            'operationId': 'getAccount',
            'security': [
              {'bearerAuth': <String>[]},
            ],
          },
          'parameters': [
            {'name': 'id', 'in': 'path', 'required': true},
          ],
        },
        '/sessions': {
          'post': {'operationId': 'createSession'},
        },
      },
      'components': {
        'securitySchemes': {
          'bearerAuth': {'type': 'http', 'scheme': 'bearer'},
        },
      },
    };

    final result = ContextIngestionService().ingestBytes(
      projectId: 9,
      fileName: 'billing.openapi.json',
      bytes: utf8.encode(jsonEncode(source)),
      ingestedAt: DateTime.utc(2026, 10, 31, 17),
    );

    expect(result.artifact.type, ContextArtifactType.apiSpecification);
    expect(result.artifact.projectId, 9);
    expect(result.artifact.originalFileName, 'billing.openapi.json');
    expect(result.artifact.sha256, hasLength(64));
    expect(result.artifact.extractionMethod, 'openapi-json-deterministic');
    expect(result.apiEndpoints, hasLength(2));
    expect(
      result.apiEndpoints.first,
      isA<ApiEndpointContext>()
          .having((value) => value.method, 'method', 'GET')
          .having((value) => value.path, 'path', '/accounts/{id}')
          .having((value) => value.operationId, 'operation', 'getAccount')
          .having((value) => value.parameterNames, 'parameters', ['id'])
          .having((value) => value.securitySchemes, 'security', ['bearerAuth']),
    );
    expect(result.apiEndpoints.last.method, 'POST');
    expect(result.apiEndpoints.last.path, '/sessions');
    expect(result.provenance.sourceDigest, result.artifact.sha256);
    expect(result.provenance.parserVersion, isNotEmpty);
  });

  test('deterministically extracts SOAP operations and service endpoints', () {
    const wsdl = '''<?xml version="1.0"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
  xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
  name="AccountService">
  <portType name="AccountPortType">
    <operation name="GetAccount" />
    <operation name="UpdateAccount" />
  </portType>
  <service name="AccountService">
    <port name="AccountPort" binding="tns:AccountBinding">
      <soap:address location="https://internal.example.test/Account.svc" />
    </port>
  </service>
</definitions>''';

    final result = ContextIngestionService().ingestBytes(
      projectId: 9,
      fileName: 'account.wsdl',
      bytes: utf8.encode(wsdl),
      ingestedAt: DateTime.utc(2026, 10, 31, 17, 5),
    );

    expect(result.artifact.type, ContextArtifactType.soapSpecification);
    expect(result.artifact.extractionMethod, 'wsdl-xml-deterministic');
    expect(result.apiEndpoints.map((item) => item.operationId), [
      'GetAccount',
      'UpdateAccount',
    ]);
    expect(result.apiEndpoints.first.method, 'SOAP');
    expect(
      result.apiEndpoints.first.path,
      'https://internal.example.test/Account.svc',
    );
  });

  test('safely inventories source archives with per-file provenance', () {
    final archive = Archive()
      ..addFile(
        ArchiveFile(
          'src/app.dart',
          utf8.encode('void main() {}').length,
          utf8.encode('void main() {}'),
        ),
      )
      ..addFile(
        ArchiveFile(
          'docs/architecture.md',
          utf8.encode('# Architecture').length,
          utf8.encode('# Architecture'),
        ),
      );
    final bytes = ZipEncoder().encode(archive);

    final result = ContextIngestionService().ingestBytes(
      projectId: 9,
      fileName: 'source.zip',
      bytes: bytes,
      ingestedAt: DateTime.utc(2026, 10, 31, 17, 10),
    );

    expect(result.artifact.type, ContextArtifactType.sourceArchive);
    expect(result.artifact.extractionMethod, 'zip-safe-inventory');
    expect(result.archiveEntries.map((entry) => entry.path), [
      'docs/architecture.md',
      'src/app.dart',
    ]);
    expect(
      result.archiveEntries.every((entry) => entry.sha256.length == 64),
      isTrue,
    );
  });

  test('rejects symbolic links in source archives', () {
    final link = ArchiveFile.bytes(
      'src/link.txt',
      utf8.encode('../../outside.txt'),
    )..mode = 0xa1ff;
    final bytes = ZipEncoder().encode(Archive()..addFile(link));
    for (var index = 0; index <= bytes.length - 6; index++) {
      if (bytes[index] == 0x50 &&
          bytes[index + 1] == 0x4b &&
          bytes[index + 2] == 0x01 &&
          bytes[index + 3] == 0x02) {
        bytes[index + 5] = 3; // UNIX creator, so mode bits identify a symlink.
        break;
      }
    }

    expect(
      () => ContextIngestionService().ingestBytes(
        projectId: 9,
        fileName: 'symlink.zip',
        bytes: bytes,
        ingestedAt: DateTime.utc(2026, 10, 31, 17, 11),
      ),
      throwsFormatException,
    );
  });

  test('rejects traversal entries in source archives', () {
    final archive = Archive()
      ..addFile(ArchiveFile('../outside.txt', 4, utf8.encode('nope')));
    final bytes = ZipEncoder().encode(archive);

    expect(
      () => ContextIngestionService().ingestBytes(
        projectId: 9,
        fileName: 'unsafe.zip',
        bytes: bytes,
        ingestedAt: DateTime.utc(2026, 10, 31, 17, 11),
      ),
      throwsFormatException,
    );
  });
}
