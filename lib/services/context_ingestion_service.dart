import 'dart:convert';
import 'dart:typed_data';
import 'dart:isolate';

import 'package:archive/archive.dart';
import 'package:crypto/crypto.dart';
import 'package:xml/xml.dart';
import 'package:yaml/yaml.dart';

import '../models/context_artifact.dart';
import 'sensitive_text_redactor.dart';

class ContextIngestionService {
  static const parserVersion = '1';
  final int maxExpandedArchiveBytes;
  final int maxArchiveEntries;

  const ContextIngestionService({
    this.maxExpandedArchiveBytes = 100 * 1024 * 1024,
    this.maxArchiveEntries = 20000,
  });

  static const _httpMethods = {
    'get',
    'post',
    'put',
    'patch',
    'delete',
    'head',
    'options',
    'trace',
  };

  Future<ContextIngestionResult> ingestBytesAsync({
    required int projectId,
    required String fileName,
    required List<int> bytes,
    required DateTime ingestedAt,
  }) => Isolate.run(
    () => ingestBytes(
      projectId: projectId,
      fileName: fileName,
      bytes: bytes,
      ingestedAt: ingestedAt,
    ),
  );

  ContextIngestionResult ingestBytes({
    required int projectId,
    required String fileName,
    required List<int> bytes,
    required DateTime ingestedAt,
  }) {
    if (projectId <= 0) throw ArgumentError.value(projectId, 'projectId');
    final data = Uint8List.fromList(bytes);
    final digest = sha256.convert(data).toString();
    final lowerName = fileName.toLowerCase();
    if (lowerName.endsWith('.zip')) {
      return _sourceArchive(
        projectId: projectId,
        fileName: fileName,
        bytes: data,
        digest: digest,
        ingestedAt: ingestedAt,
      );
    }
    final decoded = utf8.decode(data, allowMalformed: false);
    if (lowerName.endsWith('.yaml') || lowerName.endsWith('.yml')) {
      final yaml = _yamlToDart(loadYaml(decoded));
      if (yaml is Map<String, dynamic> &&
          (yaml.containsKey('openapi') || yaml.containsKey('swagger'))) {
        return _openApi(
          projectId: projectId,
          fileName: fileName,
          bytes: data,
          digest: digest,
          document: yaml,
          extractionMethod: 'openapi-yaml-deterministic',
          ingestedAt: ingestedAt,
        );
      }
    }
    if (lowerName.endsWith('.json')) {
      final value = jsonDecode(decoded);
      if (lowerName.endsWith('package.json') && value is Map<String, dynamic>) {
        return _packageJson(
          projectId: projectId,
          fileName: fileName,
          bytes: data,
          digest: digest,
          document: value,
          ingestedAt: ingestedAt,
        );
      }
      if (lowerName.contains('report') &&
          value is Map<String, dynamic> &&
          value['findings'] is List) {
        return _priorReportJson(
          projectId: projectId,
          fileName: fileName,
          bytes: data,
          digest: digest,
          document: value,
          ingestedAt: ingestedAt,
        );
      }
      if (value is Map<String, dynamic> &&
          (value.containsKey('openapi') || value.containsKey('swagger'))) {
        return _openApi(
          projectId: projectId,
          fileName: fileName,
          bytes: data,
          digest: digest,
          document: value,
          extractionMethod: 'openapi-json-deterministic',
          ingestedAt: ingestedAt,
        );
      }
    }
    if (lowerName.endsWith('.wsdl') ||
        (lowerName.endsWith('.xml') && decoded.contains('<definitions'))) {
      return _wsdl(
        projectId: projectId,
        fileName: fileName,
        bytes: data,
        digest: digest,
        document: decoded,
        ingestedAt: ingestedAt,
      );
    }
    if ((lowerName.endsWith('.md') ||
            lowerName.endsWith('.txt') ||
            lowerName.endsWith('.rst')) &&
        (lowerName.contains('architecture') || lowerName.contains('design'))) {
      return _result(
        projectId: projectId,
        fileName: fileName,
        bytes: data,
        digest: digest,
        type: ContextArtifactType.architectureDocument,
        extractionMethod: 'architecture-text-deterministic',
        ingestedAt: ingestedAt,
        normalizedText: decoded,
      );
    }
    return _result(
      projectId: projectId,
      fileName: fileName,
      bytes: data,
      digest: digest,
      type: ContextArtifactType.unknown,
      extractionMethod: 'utf8-text',
      ingestedAt: ingestedAt,
      normalizedText: decoded,
    );
  }

  ContextIngestionResult _priorReportJson({
    required int projectId,
    required String fileName,
    required Uint8List bytes,
    required String digest,
    required Map<String, dynamic> document,
    required DateTime ingestedAt,
  }) {
    final findings = <PriorFindingContext>[];
    for (final value in document['findings'] as List) {
      if (value is! Map) continue;
      final title = value['title']?.toString().trim() ?? '';
      if (title.isEmpty) continue;
      findings.add(
        PriorFindingContext(
          title: title,
          severity: value['severity']?.toString().trim().toUpperCase() ?? '',
          status: value['status']?.toString().trim().toLowerCase() ?? '',
          evidence: value['evidence']?.toString().trim() ?? '',
          remediation: value['remediation']?.toString().trim() ?? '',
        ),
      );
    }
    findings.sort((left, right) => left.title.compareTo(right.title));
    return _result(
      projectId: projectId,
      fileName: fileName,
      bytes: bytes,
      digest: digest,
      type: ContextArtifactType.priorReport,
      extractionMethod: 'prior-report-json-deterministic',
      ingestedAt: ingestedAt,
      priorFindings: findings,
      normalizedText: jsonEncode(document),
    );
  }

  ContextIngestionResult _packageJson({
    required int projectId,
    required String fileName,
    required Uint8List bytes,
    required String digest,
    required Map<String, dynamic> document,
    required DateTime ingestedAt,
  }) {
    final dependencies = <DependencyContext>[];
    void addDependencies(Object? value, {required bool developmentOnly}) {
      if (value is! Map) return;
      final names = value.keys.map((key) => key.toString()).toList()..sort();
      for (final name in names) {
        dependencies.add(
          DependencyContext(
            name: name,
            versionConstraint: value[name]?.toString() ?? '',
            ecosystem: 'npm',
            developmentOnly: developmentOnly,
          ),
        );
      }
    }

    addDependencies(document['dependencies'], developmentOnly: false);
    addDependencies(document['devDependencies'], developmentOnly: true);
    return _result(
      projectId: projectId,
      fileName: fileName,
      bytes: bytes,
      digest: digest,
      type: ContextArtifactType.dependencyManifest,
      extractionMethod: 'npm-package-json-deterministic',
      ingestedAt: ingestedAt,
      dependencies: dependencies,
      normalizedText: jsonEncode(document),
    );
  }

  ContextIngestionResult _sourceArchive({
    required int projectId,
    required String fileName,
    required Uint8List bytes,
    required String digest,
    required DateTime ingestedAt,
  }) {
    final archive = ZipDecoder().decodeBytes(bytes);
    final entries = <ContextArchiveEntry>[];
    final paths = <String>{};
    var expandedBytes = 0;
    for (final entry in archive.files) {
      if (!entry.isFile) continue;
      if (entries.length >= maxArchiveEntries) {
        throw const FormatException('Source archive contains too many files.');
      }
      final path = entry.name;
      final parts = path.split('/');
      if (entry.isSymbolicLink ||
          path.isEmpty ||
          path.startsWith('/') ||
          path.contains('\\') ||
          parts.any((part) => part.isEmpty || part == '.' || part == '..') ||
          !paths.add(path)) {
        throw const FormatException('Source archive contains an unsafe path.');
      }
      final claimedSize = entry.size;
      if (claimedSize < 0 ||
          expandedBytes + claimedSize > maxExpandedArchiveBytes) {
        throw const FormatException(
          'Source archive expands beyond the safe byte limit.',
        );
      }
      final content = Uint8List.fromList(entry.content as List<int>);
      expandedBytes += content.length;
      if (expandedBytes > maxExpandedArchiveBytes) {
        throw const FormatException(
          'Source archive expands beyond the safe byte limit.',
        );
      }
      entries.add(
        ContextArchiveEntry(
          path: path,
          sha256: sha256.convert(content).toString(),
          sizeBytes: content.length,
        ),
      );
    }
    entries.sort((left, right) => left.path.compareTo(right.path));
    return _result(
      projectId: projectId,
      fileName: fileName,
      bytes: bytes,
      digest: digest,
      type: ContextArtifactType.sourceArchive,
      extractionMethod: 'zip-safe-inventory',
      ingestedAt: ingestedAt,
      archiveEntries: entries,
    );
  }

  ContextIngestionResult _wsdl({
    required int projectId,
    required String fileName,
    required Uint8List bytes,
    required String digest,
    required String document,
    required DateTime ingestedAt,
  }) {
    final xml = XmlDocument.parse(document);
    final addresses = xml.descendants
        .whereType<XmlElement>()
        .where((element) => element.name.local == 'address')
        .map((element) => element.getAttribute('location') ?? '')
        .where((value) => value.isNotEmpty)
        .toList(growable: false);
    final endpoint = addresses.isEmpty ? '' : addresses.first;
    final operations = <String>{};
    for (final portType in xml.descendants.whereType<XmlElement>().where(
      (element) => element.name.local == 'portType',
    )) {
      for (final operation in portType.children.whereType<XmlElement>().where(
        (element) => element.name.local == 'operation',
      )) {
        final name = operation.getAttribute('name');
        if (name != null && name.isNotEmpty) operations.add(name);
      }
    }
    final endpoints =
        operations
            .map(
              (operation) => ApiEndpointContext(
                method: 'SOAP',
                path: endpoint,
                operationId: operation,
              ),
            )
            .toList(growable: false)
          ..sort(
            (left, right) => left.operationId.compareTo(right.operationId),
          );
    return _result(
      projectId: projectId,
      fileName: fileName,
      bytes: bytes,
      digest: digest,
      type: ContextArtifactType.soapSpecification,
      extractionMethod: 'wsdl-xml-deterministic',
      ingestedAt: ingestedAt,
      apiEndpoints: endpoints,
      normalizedText: document,
    );
  }

  ContextIngestionResult _openApi({
    required int projectId,
    required String fileName,
    required Uint8List bytes,
    required String digest,
    required Map<String, dynamic> document,
    required String extractionMethod,
    required DateTime ingestedAt,
  }) {
    final endpoints = <ApiEndpointContext>[];
    final paths = document['paths'];
    if (paths is Map) {
      for (final pathEntry in paths.entries) {
        final path = pathEntry.key.toString();
        final pathItem = pathEntry.value;
        if (pathItem is! Map) continue;
        final sharedParameters = _parameterNames(pathItem['parameters']);
        for (final operationEntry in pathItem.entries) {
          final method = operationEntry.key.toString().toLowerCase();
          if (!_httpMethods.contains(method)) continue;
          final operation = operationEntry.value;
          if (operation is! Map) continue;
          final parameters = <String>{
            ...sharedParameters,
            ..._parameterNames(operation['parameters']),
          }.toList(growable: false);
          final security = <String>[];
          final securityValue = operation['security'];
          if (securityValue is List) {
            for (final requirement in securityValue) {
              if (requirement is Map) {
                security.addAll(requirement.keys.map((key) => key.toString()));
              }
            }
          }
          endpoints.add(
            ApiEndpointContext(
              method: method.toUpperCase(),
              path: path,
              operationId: operation['operationId']?.toString() ?? '',
              parameterNames: List.unmodifiable(parameters),
              securitySchemes: List.unmodifiable(security.toSet()),
            ),
          );
        }
      }
    }
    endpoints.sort((left, right) {
      final pathOrder = left.path.compareTo(right.path);
      return pathOrder != 0 ? pathOrder : left.method.compareTo(right.method);
    });
    return _result(
      projectId: projectId,
      fileName: fileName,
      bytes: bytes,
      digest: digest,
      type: ContextArtifactType.apiSpecification,
      extractionMethod: extractionMethod,
      ingestedAt: ingestedAt,
      apiEndpoints: endpoints,
      normalizedText: jsonEncode(document),
    );
  }

  Set<String> _parameterNames(Object? value) {
    if (value is! List) return const {};
    return value
        .whereType<Map>()
        .map((parameter) => parameter['name']?.toString() ?? '')
        .where((name) => name.isNotEmpty)
        .toSet();
  }

  Object? _yamlToDart(Object? value) {
    if (value is YamlMap || value is Map) {
      return (value as Map).map(
        (key, item) => MapEntry(key.toString(), _yamlToDart(item)),
      );
    }
    if (value is YamlList || value is List) {
      return (value as List).map(_yamlToDart).toList(growable: false);
    }
    return value;
  }

  ContextIngestionResult _result({
    required int projectId,
    required String fileName,
    required Uint8List bytes,
    required String digest,
    required ContextArtifactType type,
    required String extractionMethod,
    required DateTime ingestedAt,
    List<ApiEndpointContext> apiEndpoints = const [],
    List<DependencyContext> dependencies = const [],
    List<PriorFindingContext> priorFindings = const [],
    List<ContextArchiveEntry> archiveEntries = const [],
    String normalizedText = '',
  }) {
    final utc = ingestedAt.toUtc();
    final artifact = ContextArtifact(
      projectId: projectId,
      type: type,
      originalFileName: fileName,
      sha256: digest,
      sizeBytes: bytes.length,
      extractionMethod: extractionMethod,
      ingestedAt: utc,
    );
    return ContextIngestionResult(
      artifact: artifact,
      provenance: ContextProvenance(
        sourceDigest: digest,
        parserVersion: parserVersion,
        sourceName: fileName,
        extractedAt: utc,
      ),
      apiEndpoints: List.unmodifiable(apiEndpoints),
      dependencies: List.unmodifiable(dependencies),
      priorFindings: List.unmodifiable(
        priorFindings.map(
          (finding) => PriorFindingContext(
            title: SensitiveTextRedactor.redact(finding.title, maxLength: 500),
            severity: finding.severity,
            status: finding.status,
            evidence: SensitiveTextRedactor.redact(
              finding.evidence,
              maxLength: 8000,
            ),
            remediation: SensitiveTextRedactor.redact(
              finding.remediation,
              maxLength: 8000,
            ),
          ),
        ),
      ),
      archiveEntries: List.unmodifiable(archiveEntries),
      normalizedText: SensitiveTextRedactor.redact(normalizedText),
    );
  }
}
