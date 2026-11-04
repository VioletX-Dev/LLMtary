import 'dart:convert';
import 'dart:typed_data';
import 'dart:isolate';

import 'package:archive/archive.dart';
import 'package:crypto/crypto.dart';
import 'package:pdf_document/pdf_document.dart';
import 'package:pdf_graphics/pdf_graphics.dart';
import 'package:xml/xml.dart';
import 'package:yaml/yaml.dart';

import '../models/context_artifact.dart';
import 'sensitive_text_redactor.dart';

class ContextIngestionService {
  static const parserVersion = '1';
  final int maxExpandedArchiveBytes;
  final int maxArchiveEntries;
  final int maxArchiveTextBytes;
  final int maxArchiveTextFileBytes;

  const ContextIngestionService({
    this.maxExpandedArchiveBytes = 100 * 1024 * 1024,
    this.maxArchiveEntries = 20000,
    this.maxArchiveTextBytes = 2 * 1024 * 1024,
    this.maxArchiveTextFileBytes = 256 * 1024,
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
    if (lowerName.endsWith('.docx')) {
      return _docx(
        projectId: projectId,
        fileName: fileName,
        bytes: data,
        digest: digest,
        ingestedAt: ingestedAt,
      );
    }
    if (lowerName.endsWith('.zip')) {
      return _sourceArchive(
        projectId: projectId,
        fileName: fileName,
        bytes: data,
        digest: digest,
        ingestedAt: ingestedAt,
      );
    }
    if (lowerName.endsWith('.pdf')) {
      return _pdf(
        projectId: projectId,
        fileName: fileName,
        bytes: data,
        digest: digest,
        ingestedAt: ingestedAt,
      );
    }
    final decoded = utf8.decode(data, allowMalformed: false);
    if (lowerName.endsWith('.yaml') ||
        lowerName.endsWith('.yml') ||
        lowerName.endsWith('pubspec.lock')) {
      final yaml = _yamlToDart(loadYaml(decoded));
      if ((lowerName.endsWith('pubspec.yaml') ||
              lowerName.endsWith('pubspec.yml')) &&
          yaml is Map<String, dynamic>) {
        return _dartManifest(
          projectId: projectId,
          fileName: fileName,
          bytes: data,
          digest: digest,
          document: yaml,
          ingestedAt: ingestedAt,
        );
      }
      if (lowerName.endsWith('pubspec.lock') && yaml is Map<String, dynamic>) {
        return _dartLock(
          projectId: projectId,
          fileName: fileName,
          bytes: data,
          digest: digest,
          document: yaml,
          ingestedAt: ingestedAt,
        );
      }
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
      if (lowerName.endsWith('package-lock.json') &&
          value is Map<String, dynamic>) {
        return _packageLock(
          projectId: projectId,
          fileName: fileName,
          bytes: data,
          digest: digest,
          document: value,
          ingestedAt: ingestedAt,
        );
      }
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
    if (lowerName.endsWith('requirements.txt') ||
        lowerName.endsWith('requirements.in')) {
      return _requirements(
        projectId: projectId,
        fileName: fileName,
        bytes: data,
        digest: digest,
        document: decoded,
        ingestedAt: ingestedAt,
      );
    }
    if (lowerName.endsWith('pyproject.toml') ||
        lowerName.endsWith('poetry.lock')) {
      return _pythonTomlManifest(
        projectId: projectId,
        fileName: fileName,
        bytes: data,
        digest: digest,
        document: decoded,
        ingestedAt: ingestedAt,
      );
    }
    if (lowerName.endsWith('pom.xml')) {
      return _mavenManifest(
        projectId: projectId,
        fileName: fileName,
        bytes: data,
        digest: digest,
        document: decoded,
        ingestedAt: ingestedAt,
      );
    }
    if (lowerName.endsWith('.gradle') || lowerName.endsWith('.gradle.kts')) {
      return _gradleManifest(
        projectId: projectId,
        fileName: fileName,
        bytes: data,
        digest: digest,
        document: decoded,
        ingestedAt: ingestedAt,
      );
    }
    if (lowerName.endsWith('.csproj') ||
        lowerName.endsWith('.fsproj') ||
        lowerName.endsWith('packages.config')) {
      return _dotnetManifest(
        projectId: projectId,
        fileName: fileName,
        bytes: data,
        digest: digest,
        document: decoded,
        ingestedAt: ingestedAt,
      );
    }
    if (lowerName.endsWith('.html') || lowerName.endsWith('.htm')) {
      return _priorReportHtml(
        projectId: projectId,
        fileName: fileName,
        bytes: data,
        digest: digest,
        document: decoded,
        ingestedAt: ingestedAt,
      );
    }
    if (lowerName.endsWith('.csv')) {
      return _priorReportCsv(
        projectId: projectId,
        fileName: fileName,
        bytes: data,
        digest: digest,
        document: decoded,
        ingestedAt: ingestedAt,
      );
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
    if (lowerName.endsWith('.md') &&
        (lowerName.contains('report') || lowerName.contains('finding'))) {
      return _result(
        projectId: projectId,
        fileName: fileName,
        bytes: data,
        digest: digest,
        type: ContextArtifactType.priorReport,
        extractionMethod: 'prior-report-markdown-deterministic',
        ingestedAt: ingestedAt,
        normalizedText: decoded,
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

  String _truncateUtf8(String value, int maxBytes) {
    if (maxBytes <= 0) return '';
    final buffer = StringBuffer();
    var used = 0;
    for (final rune in value.runes) {
      final character = String.fromCharCode(rune);
      final byteLength = utf8.encode(character).length;
      if (used + byteLength > maxBytes) break;
      buffer.write(character);
      used += byteLength;
    }
    return buffer.toString();
  }

  ContextIngestionResult _pdf({
    required int projectId,
    required String fileName,
    required Uint8List bytes,
    required String digest,
    required DateTime ingestedAt,
  }) {
    String text;
    try {
      final document = PdfDocument.open(bytes);
      final buffer = StringBuffer();
      var usedBytes = 0;
      final pageLimit = document.pageCount > 500 ? 500 : document.pageCount;
      for (var page = 0; page < pageLimit; page++) {
        final pageText = PdfTextExtractor.extract(document, page).text.trim();
        if (pageText.isEmpty) continue;
        final header = '--- page ${page + 1} ---\n';
        final headerBytes = utf8.encode(header).length;
        final remaining = maxArchiveTextBytes - usedBytes - headerBytes - 1;
        if (remaining <= 0) break;
        final selected = _truncateUtf8(pageText, remaining);
        if (selected.isEmpty) break;
        buffer
          ..write(header)
          ..writeln(selected);
        usedBytes += headerBytes + utf8.encode(selected).length + 1;
      }
      text = buffer.toString().trim();
      if (text.isEmpty) text = '[PDF contains no extractable text layer]';
    } catch (error) {
      throw FormatException('PDF parsing failed: ${error.runtimeType}');
    }
    return _result(
      projectId: projectId,
      fileName: fileName,
      bytes: bytes,
      digest: digest,
      type: ContextArtifactType.architectureDocument,
      extractionMethod: 'pdf-graphics-text-layer-bounded',
      ingestedAt: ingestedAt,
      normalizedText: text,
    );
  }

  ContextIngestionResult _docx({
    required int projectId,
    required String fileName,
    required Uint8List bytes,
    required String digest,
    required DateTime ingestedAt,
  }) {
    final archive = ZipDecoder().decodeBytes(bytes);
    final documentEntry = archive.files.where(
      (entry) => entry.isFile && entry.name == 'word/document.xml',
    );
    if (documentEntry.isEmpty) {
      throw const FormatException('DOCX document.xml is missing.');
    }
    final entry = documentEntry.single;
    if (entry.isSymbolicLink || entry.size > maxExpandedArchiveBytes) {
      throw const FormatException('DOCX document exceeds the safe byte limit.');
    }
    final content = Uint8List.fromList(entry.content as List<int>);
    if (content.length > maxExpandedArchiveBytes) {
      throw const FormatException('DOCX document exceeds the safe byte limit.');
    }
    final xml = XmlDocument.parse(utf8.decode(content, allowMalformed: false));
    final text = xml.descendants
        .whereType<XmlElement>()
        .where((element) => element.name.local == 't')
        .map((element) => element.innerText.trim())
        .where((value) => value.isNotEmpty)
        .join('\n');
    return _result(
      projectId: projectId,
      fileName: fileName,
      bytes: bytes,
      digest: digest,
      type: ContextArtifactType.architectureDocument,
      extractionMethod: 'docx-xml-bounded',
      ingestedAt: ingestedAt,
      normalizedText: text,
    );
  }

  ContextIngestionResult _priorReportHtml({
    required int projectId,
    required String fileName,
    required Uint8List bytes,
    required String digest,
    required String document,
    required DateTime ingestedAt,
  }) {
    var text = document
        .replaceAll(
          RegExp(r'<script\b[\s\S]*?<\/script\s*>', caseSensitive: false),
          ' ',
        )
        .replaceAll(
          RegExp(r'<style\b[\s\S]*?<\/style\s*>', caseSensitive: false),
          ' ',
        )
        .replaceAll(RegExp(r'<[^>]+>'), ' ')
        .replaceAll('&lt;', '<')
        .replaceAll('&gt;', '>')
        .replaceAll('&amp;', '&')
        .replaceAll(RegExp(r'\s+'), ' ')
        .trim();
    text = SensitiveTextRedactor.redact(text);
    return _result(
      projectId: projectId,
      fileName: fileName,
      bytes: bytes,
      digest: digest,
      type: ContextArtifactType.priorReport,
      extractionMethod: 'prior-report-html-deterministic',
      ingestedAt: ingestedAt,
      normalizedText: text,
    );
  }

  ContextIngestionResult _priorReportCsv({
    required int projectId,
    required String fileName,
    required Uint8List bytes,
    required String digest,
    required String document,
    required DateTime ingestedAt,
  }) {
    final rows = const _CsvParser().parse(document);
    if (rows.isEmpty) throw const FormatException('CSV report is empty.');
    final headers = rows.first
        .map((value) => value.trim().toLowerCase())
        .toList();
    final findings = <PriorFindingContext>[];
    String valueAt(List<String> row, String name) {
      final index = headers.indexOf(name);
      return index >= 0 && index < row.length ? row[index].trim() : '';
    }

    for (final row in rows.skip(1)) {
      final title = valueAt(row, 'title');
      if (title.isEmpty) continue;
      findings.add(
        PriorFindingContext(
          title: title,
          severity: valueAt(row, 'severity').toUpperCase(),
          status: valueAt(row, 'status').toLowerCase(),
          evidence: valueAt(row, 'evidence'),
          remediation: valueAt(row, 'remediation'),
        ),
      );
    }
    return _result(
      projectId: projectId,
      fileName: fileName,
      bytes: bytes,
      digest: digest,
      type: ContextArtifactType.priorReport,
      extractionMethod: 'prior-report-csv-deterministic',
      ingestedAt: ingestedAt,
      priorFindings: findings,
      normalizedText: document,
    );
  }

  ContextIngestionResult _requirements({
    required int projectId,
    required String fileName,
    required Uint8List bytes,
    required String digest,
    required String document,
    required DateTime ingestedAt,
  }) {
    final dependencies = <DependencyContext>[];
    final pattern = RegExp(r'^([A-Za-z0-9_.-]+)\s*(.*)$');
    for (final rawLine in const LineSplitter().convert(document)) {
      final line = rawLine.split('#').first.trim();
      if (line.isEmpty || line.startsWith('-')) continue;
      final match = pattern.firstMatch(line);
      if (match == null) continue;
      dependencies.add(
        DependencyContext(
          name: match.group(1)!,
          versionConstraint: (match.group(2) ?? '').trim(),
          ecosystem: 'pypi',
        ),
      );
    }
    dependencies.sort((a, b) => a.name.compareTo(b.name));
    return _dependencyResult(
      projectId,
      fileName,
      bytes,
      digest,
      ingestedAt,
      'python-requirements-deterministic',
      dependencies,
      document,
    );
  }

  ContextIngestionResult _dartManifest({
    required int projectId,
    required String fileName,
    required Uint8List bytes,
    required String digest,
    required Map<String, dynamic> document,
    required DateTime ingestedAt,
  }) {
    final dependencies = <DependencyContext>[];
    void add(Object? value, bool developmentOnly) {
      if (value is! Map) return;
      final names = value.keys.map((key) => key.toString()).toList()..sort();
      for (final name in names) {
        dependencies.add(
          DependencyContext(
            name: name,
            versionConstraint: value[name]?.toString() ?? '',
            ecosystem: 'pub',
            developmentOnly: developmentOnly,
          ),
        );
      }
    }

    add(document['dependencies'], false);
    add(document['dev_dependencies'], true);
    return _dependencyResult(
      projectId,
      fileName,
      bytes,
      digest,
      ingestedAt,
      'dart-pubspec-deterministic',
      dependencies,
      jsonEncode(document),
    );
  }

  ContextIngestionResult _dartLock({
    required int projectId,
    required String fileName,
    required Uint8List bytes,
    required String digest,
    required Map<String, dynamic> document,
    required DateTime ingestedAt,
  }) {
    final dependencies = <DependencyContext>[];
    final packages = document['packages'];
    if (packages is Map) {
      final names = packages.keys.map((key) => key.toString()).toList()..sort();
      for (final name in names) {
        final details = packages[name];
        final map = details is Map ? details : const {};
        dependencies.add(
          DependencyContext(
            name: name,
            versionConstraint: map['version']?.toString() ?? '',
            ecosystem: 'pub',
            developmentOnly: (map['dependency']?.toString() ?? '').contains(
              'dev',
            ),
          ),
        );
      }
    }
    return _dependencyResult(
      projectId,
      fileName,
      bytes,
      digest,
      ingestedAt,
      'dart-pub-lock-deterministic',
      dependencies,
      jsonEncode(document),
    );
  }

  ContextIngestionResult _packageLock({
    required int projectId,
    required String fileName,
    required Uint8List bytes,
    required String digest,
    required Map<String, dynamic> document,
    required DateTime ingestedAt,
  }) {
    final dependencies = <DependencyContext>[];
    final packages = document['packages'];
    if (packages is Map) {
      final paths = packages.keys.map((key) => key.toString()).toList()..sort();
      for (final path in paths) {
        if (!path.startsWith('node_modules/')) continue;
        final name = path.substring('node_modules/'.length);
        if (name.isEmpty || name.contains('/node_modules/')) continue;
        final details = packages[path];
        final map = details is Map ? details : const {};
        dependencies.add(
          DependencyContext(
            name: name,
            versionConstraint: map['version']?.toString() ?? '',
            ecosystem: 'npm',
            developmentOnly: map['dev'] == true,
          ),
        );
      }
    }
    return _dependencyResult(
      projectId,
      fileName,
      bytes,
      digest,
      ingestedAt,
      'npm-package-lock-deterministic',
      dependencies,
      jsonEncode(document),
    );
  }

  ContextIngestionResult _pythonTomlManifest({
    required int projectId,
    required String fileName,
    required Uint8List bytes,
    required String digest,
    required String document,
    required DateTime ingestedAt,
  }) {
    final dependencies = <DependencyContext>[];
    final seen = <String>{};
    final quoted = RegExp(r'''["']([A-Za-z0-9_.-]+)\s*([^"']*)["']''');
    for (final match in quoted.allMatches(document)) {
      final name = match.group(1) ?? '';
      if (name.isEmpty || !seen.add(name)) continue;
      dependencies.add(
        DependencyContext(
          name: name,
          versionConstraint: (match.group(2) ?? '').trim(),
          ecosystem: 'pypi',
        ),
      );
    }
    dependencies.sort((a, b) => a.name.compareTo(b.name));
    return _dependencyResult(
      projectId,
      fileName,
      bytes,
      digest,
      ingestedAt,
      'python-toml-lock-deterministic',
      dependencies,
      document,
    );
  }

  ContextIngestionResult _gradleManifest({
    required int projectId,
    required String fileName,
    required Uint8List bytes,
    required String digest,
    required String document,
    required DateTime ingestedAt,
  }) {
    final dependencies = <DependencyContext>[];
    final pattern = RegExp(
      r'''(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s*\(?\s*["']([^:"']+):([^:"']+):([^"']+)["']''',
    );
    for (final match in pattern.allMatches(document)) {
      final configuration = match.group(0) ?? '';
      dependencies.add(
        DependencyContext(
          name: '${match.group(1)}:${match.group(2)}',
          versionConstraint: match.group(3) ?? '',
          ecosystem: 'maven',
          developmentOnly: configuration.startsWith('testImplementation'),
        ),
      );
    }
    return _dependencyResult(
      projectId,
      fileName,
      bytes,
      digest,
      ingestedAt,
      'gradle-dependencies-deterministic',
      dependencies,
      document,
    );
  }

  ContextIngestionResult _mavenManifest({
    required int projectId,
    required String fileName,
    required Uint8List bytes,
    required String digest,
    required String document,
    required DateTime ingestedAt,
  }) {
    final xml = XmlDocument.parse(document);
    final dependencies = <DependencyContext>[];
    for (final element in xml.descendants.whereType<XmlElement>().where(
      (element) => element.name.local == 'dependency',
    )) {
      String child(String name) => element.children
          .whereType<XmlElement>()
          .where((value) => value.name.local == name)
          .map((value) => value.innerText.trim())
          .firstWhere((value) => value.isNotEmpty, orElse: () => '');
      final artifact = child('artifactId');
      if (artifact.isEmpty) continue;
      final group = child('groupId');
      dependencies.add(
        DependencyContext(
          name: group.isEmpty ? artifact : '$group:$artifact',
          versionConstraint: child('version'),
          ecosystem: 'maven',
          developmentOnly: child('scope') == 'test',
        ),
      );
    }
    return _dependencyResult(
      projectId,
      fileName,
      bytes,
      digest,
      ingestedAt,
      'maven-pom-deterministic',
      dependencies,
      document,
    );
  }

  ContextIngestionResult _dotnetManifest({
    required int projectId,
    required String fileName,
    required Uint8List bytes,
    required String digest,
    required String document,
    required DateTime ingestedAt,
  }) {
    final xml = XmlDocument.parse(document);
    final dependencies = <DependencyContext>[];
    for (final element in xml.descendants.whereType<XmlElement>().where(
      (element) =>
          element.name.local == 'PackageReference' ||
          element.name.local == 'package',
    )) {
      final name =
          element.getAttribute('Include') ?? element.getAttribute('id') ?? '';
      if (name.isEmpty) continue;
      final version =
          element.getAttribute('Version') ??
          element.getAttribute('version') ??
          element.children
              .whereType<XmlElement>()
              .where((value) => value.name.local == 'Version')
              .map((value) => value.innerText.trim())
              .firstWhere((value) => value.isNotEmpty, orElse: () => '');
      dependencies.add(
        DependencyContext(
          name: name,
          versionConstraint: version,
          ecosystem: 'nuget',
        ),
      );
    }
    return _dependencyResult(
      projectId,
      fileName,
      bytes,
      digest,
      ingestedAt,
      'dotnet-package-deterministic',
      dependencies,
      document,
    );
  }

  ContextIngestionResult _dependencyResult(
    int projectId,
    String fileName,
    Uint8List bytes,
    String digest,
    DateTime ingestedAt,
    String method,
    List<DependencyContext> dependencies,
    String normalized,
  ) => _result(
    projectId: projectId,
    fileName: fileName,
    bytes: bytes,
    digest: digest,
    type: ContextArtifactType.dependencyManifest,
    extractionMethod: method,
    ingestedAt: ingestedAt,
    dependencies: dependencies,
    normalizedText: normalized,
  );

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
    var extractedTextBytes = 0;
    final selectedText = StringBuffer();
    const textExtensions = <String>{
      '.dart',
      '.py',
      '.js',
      '.ts',
      '.java',
      '.kt',
      '.go',
      '.rs',
      '.rb',
      '.php',
      '.cs',
      '.xml',
      '.json',
      '.yaml',
      '.yml',
      '.toml',
      '.ini',
      '.conf',
      '.properties',
      '.md',
      '.txt',
      '.rst',
      '.html',
      '.css',
      '.sql',
      '.graphql',
      '.proto',
      '.sh',
      '.ps1',
      '.gradle',
    };
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
      final lowerPath = path.toLowerCase();
      final dot = lowerPath.lastIndexOf('.');
      final extension = dot < 0 ? '' : lowerPath.substring(dot);
      if (textExtensions.contains(extension) &&
          content.length <= maxArchiveTextFileBytes &&
          extractedTextBytes < maxArchiveTextBytes) {
        try {
          final decoded = utf8.decode(content, allowMalformed: false);
          final remaining = maxArchiveTextBytes - extractedTextBytes;
          final selected = decoded.length <= remaining
              ? decoded
              : decoded.substring(0, remaining);
          selectedText
            ..writeln('--- $path ---')
            ..writeln(selected);
          extractedTextBytes += utf8.encode(selected).length;
        } on FormatException {
          // Non-UTF8 entries remain in the deterministic inventory only.
        }
      }
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
      normalizedText: selectedText.toString(),
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

class _CsvParser {
  const _CsvParser();

  List<List<String>> parse(String source) {
    final rows = <List<String>>[];
    var row = <String>[];
    var field = StringBuffer();
    var quoted = false;
    for (var index = 0; index < source.length; index++) {
      final character = source[index];
      if (character == '"') {
        if (quoted && index + 1 < source.length && source[index + 1] == '"') {
          field.write('"');
          index++;
        } else {
          quoted = !quoted;
        }
      } else if (character == ',' && !quoted) {
        row.add(field.toString());
        field = StringBuffer();
      } else if ((character == '\n' || character == '\r') && !quoted) {
        if (character == '\r' &&
            index + 1 < source.length &&
            source[index + 1] == '\n') {
          index++;
        }
        row.add(field.toString());
        field = StringBuffer();
        if (row.any((value) => value.isNotEmpty)) rows.add(row);
        row = <String>[];
      } else {
        field.write(character);
      }
    }
    if (quoted) {
      throw const FormatException('CSV contains an unterminated quote.');
    }
    row.add(field.toString());
    if (row.any((value) => value.isNotEmpty)) rows.add(row);
    return rows;
  }
}
