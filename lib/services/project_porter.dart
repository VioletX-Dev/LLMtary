import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'package:archive/archive.dart';
import '../utils/file_dialog.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:pointycastle/export.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';
import '../database/database_helper.dart';
import '../models/project.dart';
import '../models/target.dart';
import '../services/storage_service.dart';
import '../services/evidence_portability_service.dart';
import '../services/evidence_storage_service.dart';
import '../widgets/admin_password_dialog.dart';

// Top-level functions required by compute() (must be top-level or static)
Map<String, dynamic> _encryptIsolate(Map<String, dynamic> args) {
  final plaintext = args['plaintext'] as Uint8List;
  final password = args['password'] as String;
  final salt = args['salt'] as Uint8List;
  final iv = args['iv'] as Uint8List;
  final key = _deriveKeySync(password, salt);
  final cipher = GCMBlockCipher(AESEngine())
    ..init(true, AEADParameters(KeyParameter(key), 128, iv, Uint8List(0)));
  final ciphertext = cipher.process(plaintext);
  return {'salt': salt, 'iv': iv, 'ciphertext': ciphertext};
}

Uint8List _decryptIsolate(Map<String, dynamic> args) {
  final data = args['data'] as Uint8List;
  final password = args['password'] as String;
  if (data.length < 16 + 12 + 16) throw Exception('File too short');
  final salt = data.sublist(0, 16);
  final iv = data.sublist(16, 28);
  final ciphertext = data.sublist(28);
  final key = _deriveKeySync(password, salt);
  final cipher = GCMBlockCipher(AESEngine())
    ..init(false, AEADParameters(KeyParameter(key), 128, iv, Uint8List(0)));
  return cipher.process(ciphertext);
}

Map<String, Uint8List> _decodeZipIsolate(Uint8List bytes) {
  final archive = ZipDecoder().decodeBytes(bytes);
  final files = <String, Uint8List>{};
  var totalBytes = 0;
  for (final entry in archive.files) {
    if (!entry.isFile) continue;
    final name = entry.name;
    final components = name.split('/');
    if (name.startsWith('/') ||
        name.contains('\\') ||
        components.any((part) => part == '.' || part == '..') ||
        files.containsKey(name)) {
      throw const FormatException('Project archive contains an unsafe path.');
    }
    final content = Uint8List.fromList(entry.content as List<int>);
    totalBytes += content.length;
    if (totalBytes > ProjectPorter.maxExpandedProjectBytes) {
      throw const FormatException(
        'Project archive expands beyond the safe limit.',
      );
    }
    files[name] = content;
  }
  return files;
}

Map<String, dynamic> _parseManifestIsolate(Uint8List bytes) {
  const maxManifestBytes = 2 * 1024 * 1024;
  const maxNodes = 100000;
  const maxDepth = 16;
  const maxStringLength = 65536;
  const collectionLimits = <String, int>{
    'targets': 1000,
    'vulnerabilities': 10000,
    'credentials': 10000,
    'commandLogs': 50000,
    'executedCommands': 50000,
    'visual_evidence': 5000,
    'validation_runs': 20000,
  };

  if (bytes.length > maxManifestBytes) {
    throw const FormatException('Project manifest exceeds the 2 MiB limit.');
  }
  final decoded = jsonDecode(utf8.decode(bytes, allowMalformed: false));
  if (decoded is! Map) {
    throw const FormatException('Project manifest must be a JSON object.');
  }

  var nodes = 0;
  void validateNode(Object? value, int depth) {
    nodes++;
    if (nodes > maxNodes || depth > maxDepth) {
      throw const FormatException('Project manifest is too complex.');
    }
    if (value is String) {
      if (value.length > maxStringLength) {
        throw const FormatException('Project manifest field is too long.');
      }
      return;
    }
    if (value is List) {
      for (final item in value) {
        validateNode(item, depth + 1);
      }
      return;
    }
    if (value is Map) {
      for (final entry in value.entries) {
        final key = entry.key;
        if (key is! String || key.length > 256) {
          throw const FormatException(
            'Project manifest contains an invalid key.',
          );
        }
        validateNode(entry.value, depth + 1);
      }
      return;
    }
    if (value != null && value is! num && value is! bool) {
      throw const FormatException(
        'Project manifest contains an invalid value.',
      );
    }
  }

  validateNode(decoded, 0);
  for (final limit in collectionLimits.entries) {
    final collection = decoded[limit.key];
    if (collection != null && collection is! List) {
      throw FormatException('${limit.key} must be a list.');
    }
    if (collection is List && collection.length > limit.value) {
      throw FormatException('${limit.key} exceeds the import limit.');
    }
  }
  return Map<String, dynamic>.from(decoded);
}

Uint8List _deriveKeySync(String password, Uint8List salt) {
  final pbkdf2 = PBKDF2KeyDerivator(HMac(SHA256Digest(), 64))
    ..init(Pbkdf2Parameters(salt, 200000, 32));
  return pbkdf2.process(utf8.encode(password));
}

class ProjectPorter {
  static const int maxEncryptedProjectBytes = 128 * 1024 * 1024;
  static const int maxExpandedProjectBytes = 128 * 1024 * 1024;
  static const int maxArchiveEntries = 500;

  static Future<Map<String, dynamic>> parseManifestForTesting(
    Uint8List bytes,
  ) => compute(_parseManifestIsolate, bytes);

  static void validateZipEnvelope(Uint8List bytes) {
    if (bytes.length < 22 || bytes.length > maxEncryptedProjectBytes) {
      throw const FormatException(
        'Project archive size is outside safe limits.',
      );
    }
    int read16(int offset) => bytes[offset] | (bytes[offset + 1] << 8);
    int read32(int offset) => read16(offset) | (read16(offset + 2) << 16);

    final minimum = bytes.length > 65557 ? bytes.length - 65557 : 0;
    var eocd = -1;
    for (var offset = bytes.length - 22; offset >= minimum; offset--) {
      if (read32(offset) == 0x06054b50) {
        eocd = offset;
        break;
      }
    }
    if (eocd < 0) {
      throw const FormatException('Project archive has no ZIP directory.');
    }
    final entriesOnDisk = read16(eocd + 8);
    final entryCount = read16(eocd + 10);
    final centralSize = read32(eocd + 12);
    final centralOffset = read32(eocd + 16);
    if (entryCount != entriesOnDisk ||
        entryCount > maxArchiveEntries ||
        centralOffset + centralSize != eocd) {
      throw const FormatException(
        'Project archive directory exceeds safe limits.',
      );
    }

    var offset = centralOffset;
    var totalExpanded = 0;
    for (var index = 0; index < entryCount; index++) {
      if (offset + 46 > bytes.length || read32(offset) != 0x02014b50) {
        throw const FormatException('Project archive directory is malformed.');
      }
      final flags = read16(offset + 8);
      final method = read16(offset + 10);
      final compressed = read32(offset + 20);
      final expanded = read32(offset + 24);
      final nameLength = read16(offset + 28);
      final extraLength = read16(offset + 30);
      final commentLength = read16(offset + 32);
      final diskStart = read16(offset + 34);
      final localOffset = read32(offset + 42);
      if (compressed == 0xffffffff || expanded == 0xffffffff) {
        throw const FormatException(
          'ZIP64 project archives are not supported.',
        );
      }
      if (diskStart != 0 ||
          flags & 0x09 != 0 ||
          localOffset + 30 > centralOffset ||
          read32(localOffset) != 0x04034b50 ||
          read16(localOffset + 6) != flags ||
          read16(localOffset + 8) != method ||
          read32(localOffset + 18) != compressed ||
          read32(localOffset + 22) != expanded) {
        throw const FormatException('Project archive headers do not match.');
      }
      final localNameLength = read16(localOffset + 26);
      final localExtraLength = read16(localOffset + 28);
      if (localOffset + 30 + localNameLength + localExtraLength + compressed >
          centralOffset) {
        throw const FormatException(
          'Project archive entry exceeds safe bounds.',
        );
      }
      totalExpanded += expanded;
      if (expanded > maxExpandedProjectBytes ||
          totalExpanded > maxExpandedProjectBytes ||
          (expanded > 1024 * 1024 &&
              (compressed == 0 || expanded > compressed * 200))) {
        throw const FormatException(
          'Project archive expansion exceeds safe limits.',
        );
      }
      offset += 46 + nameLength + extraLength + commentLength;
    }
  }

  // ── Public API ─────────────────────────────────────────────────────────────

  static Future<void> exportProject(
    Project project,
    BuildContext context,
  ) async {
    final password = await showDialog<String>(
      context: context,
      barrierDismissible: false,
      builder: (_) =>
          const AdminPasswordDialog(mode: PasswordDialogMode.exportConfirm),
    );
    if (password == null || password.isEmpty) return;

    if (!context.mounted) return;
    _showProgressDialog(context, 'Encrypting project…');

    try {
      debugPrint('[ProjectPorter] Building zip for "${project.name}"');
      final zipBytes = await _buildZip(project);
      debugPrint(
        '[ProjectPorter] Zip built (${zipBytes.length} bytes), encrypting…',
      );

      final salt = _randomBytes(16);
      final iv = _randomBytes(12);
      final result = await compute(_encryptIsolate, {
        'plaintext': zipBytes,
        'password': password,
        'salt': salt,
        'iv': iv,
      });
      final encrypted = Uint8List.fromList([
        ...result['salt'] as Uint8List,
        ...result['iv'] as Uint8List,
        ...result['ciphertext'] as Uint8List,
      ]);
      debugPrint(
        '[ProjectPorter] Encryption complete (${encrypted.length} bytes)',
      );

      if (context.mounted) Navigator.of(context, rootNavigator: true).pop();

      final savePath = await FileDialog.saveFile(
        dialogTitle: 'Export Project',
        fileName: '${project.name}.penex',
      );
      if (savePath == null) return;

      await File(savePath).writeAsBytes(encrypted);
      debugPrint('[ProjectPorter] Exported to $savePath');

      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Project exported to $savePath')),
        );
      }
    } catch (e, st) {
      debugPrint('[ProjectPorter] Export failed: $e\n$st');
      if (context.mounted) {
        Navigator.of(context, rootNavigator: true).pop();
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text('Export failed: $e')));
      }
    }
  }

  static Future<Project?> importProject(BuildContext context) async {
    final result = await FileDialog.pickFiles(dialogTitle: 'Import Project');
    if (result == null || result.files.single.path == null) return null;

    final password = await showDialog<String>(
      context: context,
      barrierDismissible: false,
      builder: (_) =>
          const AdminPasswordDialog(mode: PasswordDialogMode.importSingle),
    );
    if (password == null || password.isEmpty) return null;

    if (!context.mounted) return null;
    _showProgressDialog(context, 'Decrypting project…');

    try {
      debugPrint('[ProjectPorter] Reading file: ${result.files.single.path}');
      final importFile = File(result.files.single.path!);
      final encryptedSize = await importFile.length();
      if (encryptedSize <= 0 || encryptedSize > maxEncryptedProjectBytes) {
        throw const FormatException(
          'Encrypted project exceeds the 128 MiB limit.',
        );
      }
      final fileBytes = await importFile.readAsBytes();
      debugPrint(
        '[ProjectPorter] File read (${fileBytes.length} bytes), decrypting…',
      );

      final Uint8List zipBytes;
      try {
        zipBytes = await compute(_decryptIsolate, {
          'data': fileBytes,
          'password': password,
        });
        debugPrint(
          '[ProjectPorter] Decryption successful (${zipBytes.length} bytes)',
        );
        validateZipEnvelope(zipBytes);
      } catch (e) {
        debugPrint('[ProjectPorter] Decryption failed: $e');
        if (context.mounted) {
          Navigator.of(context, rootNavigator: true).pop();
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('Incorrect password or corrupted file'),
            ),
          );
        }
        return null;
      }

      if (!context.mounted) return null;
      Navigator.of(context, rootNavigator: true).pop();
      _showProgressDialog(context, 'Importing project…');

      if (!context.mounted) return null;
      final project = await _extractAndImport(zipBytes, context);
      if (context.mounted) Navigator.of(context, rootNavigator: true).pop();
      return project;
    } catch (e, st) {
      debugPrint('[ProjectPorter] Import failed: $e\n$st');
      if (context.mounted) {
        Navigator.of(context, rootNavigator: true).pop();
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text('Import failed: $e')));
      }
      return null;
    }
  }

  static void _showProgressDialog(BuildContext context, String message) {
    showDialog<void>(
      context: context,
      barrierDismissible: false,
      builder: (_) => PopScope(
        canPop: false,
        child: AlertDialog(
          backgroundColor: const Color(0xFF1A1F3A),
          content: Row(
            children: [
              const CircularProgressIndicator(color: Color(0xFF00F5FF)),
              const SizedBox(width: 20),
              Text(message, style: const TextStyle(color: Colors.white70)),
            ],
          ),
        ),
      ),
    );
  }

  // ── ZIP builder ────────────────────────────────────────────────────────────

  static Future<Uint8List> _buildZip(Project project) async {
    final projectId = project.id!;
    final targets = await DatabaseHelper.getTargets(projectId);
    final vulns = await DatabaseHelper.getVulnerabilities(projectId);
    final cmdLogs = await DatabaseHelper.getCommandLogs(projectId);
    final promptMaps = await DatabaseHelper.getPromptLogs(projectId);
    final debugMaps = await DatabaseHelper.getDebugLogs(projectId);
    final creds = await DatabaseHelper.getCredentialsByProject(projectId);
    final tokenUsageRows = await DatabaseHelper.getTokenUsage(projectId);
    final validationRuns = await DatabaseHelper.getValidationRuns(projectId);
    final db = await DatabaseHelper.database;
    final execCmdRows = await db.query(
      'executed_commands',
      where: 'projectId = ?',
      whereArgs: [projectId],
    );

    // Build address → portable path map
    final targetEntries = <Map<String, dynamic>>[];
    final fileEntries = <String, Uint8List>{};
    final evidenceArtifacts = await DatabaseHelper.getProjectEvidence(
      projectId,
    );
    final portableEvidence = await EvidencePortabilityService.export(
      project: project,
      artifacts: evidenceArtifacts,
    );
    fileEntries.addAll(portableEvidence.files);

    for (final t in targets) {
      final safeAddr = StorageService.safeTargetDirectoryName(t.address);
      final portablePath = 'files/$safeAddr/recon.json';
      targetEntries.add({
        'address': t.address,
        'jsonFilePath': portablePath,
        'summary': t.summary,
        'status': t.status.name,
        'analysisComplete': t.analysisComplete,
        'executionComplete': t.executionComplete,
      });
      if (t.jsonFilePath.isNotEmpty && await File(t.jsonFilePath).exists()) {
        fileEntries[portablePath] = await File(t.jsonFilePath).readAsBytes();
      }
      // Include all other files in the target directory
      final targetDir = Directory(
        t.jsonFilePath.isNotEmpty ? File(t.jsonFilePath).parent.path : '',
      );
      if (targetDir.path.isNotEmpty && await targetDir.exists()) {
        await for (final entity in targetDir.list()) {
          if (entity is File && entity.path != t.jsonFilePath) {
            final originalName = entity.path.split(Platform.pathSeparator).last;
            final portableName = StorageService.portableArchiveFileName(
              originalName,
            );
            var archivePath = 'files/$safeAddr/$portableName';
            var collision = 1;
            while (fileEntries.containsKey(archivePath)) {
              archivePath = 'files/$safeAddr/$collision-$portableName';
              collision++;
            }
            fileEntries[archivePath] = await entity.readAsBytes();
          }
        }
      }
    }

    // Strip machine-specific IDs, cross-reference by address
    final addressById = {for (final t in targets) t.id: t.address};

    final vulnEntries = vulns
        .map(
          (v) => {
            'portable_id': v.id,
            'targetAddress': v.targetAddress,
            'problem': v.problem,
            'cve': v.cve,
            'description': v.description,
            'severity': v.severity,
            'confidence': v.confidence,
            'evidence': v.evidence,
            'recommendation': v.recommendation,
            'attackVector': v.attackVector,
            'attackComplexity': v.attackComplexity,
            'privilegesRequired': v.privilegesRequired,
            'userInteraction': v.userInteraction,
            'scope': v.scope,
            'confidentialityImpact': v.confidentialityImpact,
            'integrityImpact': v.integrityImpact,
            'availabilityImpact': v.availabilityImpact,
            'vulnerabilityType': v.vulnerabilityType,
            'businessRisk': v.businessRisk,
            'statusReason': v.statusReason,
            'proofCommand': v.proofCommand,
            'proofCommandExpectedOutput': v.proofCommandExpectedOutput,
            'proofOutput': v.proofOutput,
            'reproductionSteps': v.reproductionSteps,
            'confirmedAt': v.confirmedAt?.toIso8601String(),
            'remediationClass': v.remediationClass.name,
            'status': v.status.name,
          },
        )
        .toList();

    final validationEntries = validationRuns
        .map(
          (run) => {
            'targetAddress': addressById[run.targetId] ?? '',
            'vulnerability_portable_id': run.vulnerabilityId,
            'mode': run.mode.name,
            'title': run.title,
            'objective': run.objective,
            // Operator parameters may contain environment-specific test values.
            // Keep the full value appliance-local; only its presence is portable.
            'parameters': run.parameters.isEmpty
                ? ''
                : '[REDACTED - retained only on source appliance]',
            'expectedResult': run.expectedResult,
            'constraints': run.constraints,
            'statusBefore': run.statusBefore,
            'statusAfter': run.statusAfter,
            'outcome': run.outcome.name,
            'summary': run.summary,
            'startedAt': run.startedAt.toIso8601String(),
            'completedAt': run.completedAt?.toIso8601String(),
          },
        )
        .toList();

    final cmdEntries = cmdLogs
        .map(
          (c) => {
            'targetAddress': addressById[c.targetId] ?? '',
            'timestamp': c.timestamp.toIso8601String(),
            'command': c.command,
            'output': c.output,
            'exitCode': c.exitCode,
            'vulnerabilityIndex': c.vulnerabilityIndex,
          },
        )
        .toList();

    final promptEntries = promptMaps
        .map(
          (m) => {
            'targetAddress': addressById[m['targetId'] as int?] ?? '',
            'prompt': m['prompt'],
            'response': m['response'],
            'timestamp': m['timestamp'],
          },
        )
        .toList();

    final debugEntries = debugMaps
        .map(
          (m) => {
            'targetAddress': addressById[m['targetId'] as int?] ?? '',
            'message': m['message'],
            'timestamp': m['timestamp'],
          },
        )
        .toList();

    final credEntries = creds
        .map(
          (c) => {
            'service': c.service,
            'host': c.host,
            'username': c.username,
            'secret': c.secret,
            'secret_type': c.secretType,
            'source_vuln': c.sourceVuln,
            'discovered_at': c.discoveredAt.toIso8601String(),
            'credential_source': c.credentialSource.name,
          },
        )
        .toList();

    final tokenEntries = tokenUsageRows
        .map(
          (r) => {
            'target_id': addressById[r['target_id'] as int?] ?? '',
            'phase': r['phase'],
            'tokens_sent': r['tokens_sent'],
            'tokens_received': r['tokens_received'],
            'recorded_at': r['recorded_at'],
          },
        )
        .toList();

    final execCmdEntries = execCmdRows
        .map(
          (r) => {
            'target_address': addressById[r['targetId'] as int?] ?? '',
            'command_normalized': r['command_normalized'],
            'output': r['output'],
            'exit_code': r['exit_code'],
            'executed_at': r['executed_at'],
          },
        )
        .toList();

    final manifest = {
      'penex_version': 4,
      'exported_at': DateTime.now().toUtc().toIso8601String(),
      'exported_from_os': Platform.operatingSystem,
      'project': {
        'name': project.name,
        'folderPath': '',
        'createdAt': project.createdAt.toIso8601String(),
        'lastOpenedAt': project.lastOpenedAt.toIso8601String(),
        'scanComplete': project.scanComplete,
        'analysisComplete': project.analysisComplete,
        'hasResults': project.hasResults,
        'first_analysis_at': project.firstAnalysisAt?.toIso8601String(),
        'last_execution_at': project.lastExecutionAt?.toIso8601String(),
        'report_title': project.reportTitle,
        'pentester_name': project.pentesterName,
        'executive_summary': project.executiveSummary,
        'methodology': project.methodology,
        'risk_rating_model': project.riskRatingModel,
        'conclusion': project.conclusion,
        'scope': project.scope,
        'scope_exclusions': project.scopeExclusions,
        'scope_notes': project.scopeNotes,
      },
      'targets': targetEntries,
      'vulnerabilities': vulnEntries,
      'visual_evidence': portableEvidence.entries,
      'command_logs': cmdEntries,
      'prompt_logs': promptEntries,
      'debug_logs': debugEntries,
      'credentials': credEntries,
      'token_usage': tokenEntries,
      'executed_commands': execCmdEntries,
      'validation_runs': validationEntries,
    };

    final archive = Archive();
    final manifestBytes = utf8.encode(
      const JsonEncoder.withIndent('  ').convert(manifest),
    );
    archive.addFile(
      ArchiveFile('manifest.json', manifestBytes.length, manifestBytes),
    );
    for (final entry in fileEntries.entries) {
      archive.addFile(ArchiveFile(entry.key, entry.value.length, entry.value));
    }

    return Uint8List.fromList(ZipEncoder().encode(archive));
  }

  // ── Encryption (AES-256-GCM, PBKDF2-SHA256) ───────────────────────────────

  static Uint8List _randomBytes(int length) {
    final random = Random.secure();
    return Uint8List.fromList(
      List<int>.generate(length, (_) => random.nextInt(256)),
    );
  }

  // ── Import extractor ───────────────────────────────────────────────────────

  static Future<Project?> _extractAndImport(
    Uint8List zipBytes,
    BuildContext context,
  ) async {
    validateZipEnvelope(zipBytes);
    final archiveFiles = await compute(_decodeZipIsolate, zipBytes);
    final manifestBytes = archiveFiles['manifest.json'];
    if (manifestBytes == null) {
      throw Exception('Invalid .penex file: missing manifest.json');
    }

    final manifest = await compute(_parseManifestIsolate, manifestBytes);
    final projectData = manifest['project'] as Map<String, dynamic>;
    String projectName = projectData['name'] as String;

    // Check for name collision
    final existing = await DatabaseHelper.getProjects();
    if (existing.any(
      (p) => p.name.toLowerCase() == projectName.toLowerCase(),
    )) {
      if (!context.mounted) return null;
      final renamed = await _promptRename(context, projectName);
      if (renamed == null) return null;
      projectName = renamed;
    }
    StorageService.validateProjectName(projectName);
    if (existing.any(
      (project) => project.name.toLowerCase() == projectName.toLowerCase(),
    )) {
      throw StateError('The imported project name is already in use.');
    }

    Project? rollbackProject;
    String? rollbackFolderPath;
    try {
      final folderPath = await StorageService.createNewProjectPath(projectName);
      rollbackFolderPath = folderPath;
      final now = DateTime.now();

      // Insert project row
      final project = Project(
        name: projectName,
        folderPath: folderPath,
        createdAt:
            DateTime.tryParse(projectData['createdAt'] as String? ?? '') ?? now,
        lastOpenedAt: now,
        scanComplete: projectData['scanComplete'] as bool? ?? false,
        analysisComplete: projectData['analysisComplete'] as bool? ?? false,
        hasResults: projectData['hasResults'] as bool? ?? false,
        firstAnalysisAt: DateTime.tryParse(
          projectData['first_analysis_at'] as String? ?? '',
        ),
        lastExecutionAt: DateTime.tryParse(
          projectData['last_execution_at'] as String? ?? '',
        ),
        reportTitle: projectData['report_title'] as String?,
        pentesterName: projectData['pentester_name'] as String?,
        executiveSummary: projectData['executive_summary'] as String?,
        methodology: projectData['methodology'] as String?,
        riskRatingModel: projectData['risk_rating_model'] as String?,
        conclusion: projectData['conclusion'] as String?,
        scope: projectData['scope'] as String?,
        scopeExclusions: projectData['scope_exclusions'] as String?,
        scopeNotes: projectData['scope_notes'] as String?,
      );
      final projectId = await DatabaseHelper.insertProject(project);
      final insertedProject = Project(
        id: projectId,
        name: project.name,
        folderPath: project.folderPath,
        createdAt: project.createdAt,
        lastOpenedAt: project.lastOpenedAt,
        scanComplete: project.scanComplete,
        analysisComplete: project.analysisComplete,
        hasResults: project.hasResults,
        firstAnalysisAt: project.firstAnalysisAt,
        lastExecutionAt: project.lastExecutionAt,
        reportTitle: project.reportTitle,
        pentesterName: project.pentesterName,
        executiveSummary: project.executiveSummary,
        methodology: project.methodology,
        riskRatingModel: project.riskRatingModel,
        conclusion: project.conclusion,
        scope: project.scope,
        scopeExclusions: project.scopeExclusions,
        scopeNotes: project.scopeNotes,
      );
      rollbackProject = insertedProject;

      // Insert targets + write recon files, build address → targetId map
      final addressToTargetId = <String, int>{};
      final targetList = (manifest['targets'] as List? ?? [])
          .cast<Map<String, dynamic>>();

      for (final t in targetList) {
        final address = t['address'] as String;
        final portablePath = t['jsonFilePath'] as String;
        final safeAddr = StorageService.safeTargetDirectoryName(address);
        final destDir = await StorageService.getTargetPath(
          projectName,
          address,
        );
        final destPath = '$destDir/$safeAddr.json';

        // Write recon file if present in archive
        final fileEntry = archiveFiles[portablePath];
        if (fileEntry != null) {
          await File(destPath).writeAsBytes(fileEntry);
        }

        // Restore all other files for this target from the archive
        final separator = portablePath.lastIndexOf('/');
        final prefix = separator >= 0
            ? portablePath.substring(0, separator + 1)
            : 'files/$safeAddr/';
        for (final entry in archiveFiles.entries) {
          if (entry.key.startsWith(prefix) && entry.key != portablePath) {
            final fileName = entry.key.substring(prefix.length);
            if (fileName.isNotEmpty && !fileName.contains('/')) {
              StorageService.validatePortableFileName(fileName);
              await File('$destDir/$fileName').writeAsBytes(entry.value);
            }
          }
        }

        final target = Target(
          projectId: projectId,
          address: address,
          jsonFilePath: fileEntry != null ? destPath : '',
          summary: t['summary'] as String? ?? '',
          status: TargetStatus.values.firstWhere(
            (e) => e.name == t['status'],
            orElse: () => TargetStatus.complete,
          ),
          analysisComplete: t['analysisComplete'] as bool? ?? false,
          executionComplete: t['executionComplete'] as bool? ?? false,
        );
        final targetId = await DatabaseHelper.insertTarget(projectId, target);
        addressToTargetId[address] = targetId;
      }

      final db = await DatabaseHelper.database;
      final vulnerabilityIdMap = <int, int>{};
      await db.transaction((txn) async {
        // Insert vulnerabilities
        for (final v
            in (manifest['vulnerabilities'] as List? ?? [])
                .cast<Map<String, dynamic>>()) {
          final addr = v['targetAddress'] as String? ?? '';
          final targetId = addressToTargetId[addr] ?? 0;
          final insertedVulnerabilityId = await txn.insert('vulnerabilities', {
            'projectId': projectId,
            'targetId': targetId,
            'targetAddress': addr,
            'problem': v['problem'] ?? '',
            'cve': v['cve'] ?? '',
            'description': v['description'] ?? '',
            'severity': v['severity'] ?? '',
            'confidence': v['confidence'] ?? '',
            'evidence': v['evidence'] ?? '',
            'recommendation': v['recommendation'] ?? '',
            'attackVector': v['attackVector'] ?? 'NETWORK',
            'attackComplexity': v['attackComplexity'] ?? 'LOW',
            'privilegesRequired': v['privilegesRequired'] ?? 'NONE',
            'userInteraction': v['userInteraction'] ?? 'NONE',
            'scope': v['scope'] ?? 'UNCHANGED',
            'confidentialityImpact': v['confidentialityImpact'] ?? 'NONE',
            'integrityImpact': v['integrityImpact'] ?? 'NONE',
            'availabilityImpact': v['availabilityImpact'] ?? 'NONE',
            'vulnerabilityType': v['vulnerabilityType'] ?? '',
            'businessRisk': v['businessRisk'] ?? '',
            'statusReason': v['statusReason'] ?? '',
            'proofCommand': v['proofCommand'],
            'proofCommandExpectedOutput': v['proofCommandExpectedOutput'],
            'proofOutput': v['proofOutput'],
            'reproductionSteps': v['reproductionSteps'],
            'confirmedAt': v['confirmedAt'],
            'remediationClass': v['remediationClass'] ?? 'unclassified',
            'status': v['status'] ?? 'pending',
          });
          final portableId = (v['portable_id'] as num?)?.toInt();
          if (portableId != null) {
            vulnerabilityIdMap[portableId] = insertedVulnerabilityId;
          }
        }

        // Restore targeted retest and spot-test history after vulnerability IDs
        // have been remapped to this imported project.
        for (final run
            in (manifest['validation_runs'] as List? ?? [])
                .cast<Map<String, dynamic>>()) {
          final addr = run['targetAddress'] as String? ?? '';
          final targetId = addressToTargetId[addr];
          if (targetId == null) {
            throw const FormatException(
              'Validation history references an unknown target.',
            );
          }
          final portableVulnerabilityId =
              (run['vulnerability_portable_id'] as num?)?.toInt();
          final vulnerabilityId = portableVulnerabilityId == null
              ? null
              : vulnerabilityIdMap[portableVulnerabilityId];
          if (portableVulnerabilityId != null && vulnerabilityId == null) {
            throw const FormatException(
              'Validation history references an unknown finding.',
            );
          }
          await txn.insert('validation_runs', {
            'projectId': projectId,
            'targetId': targetId,
            'vulnerabilityId': vulnerabilityId,
            'mode': run['mode'] ?? 'spotTest',
            'title': run['title'] ?? '',
            'objective': run['objective'] ?? '',
            'parameters': run['parameters'] ?? '',
            'expectedResult': run['expectedResult'] ?? '',
            'constraints': run['constraints'] ?? '',
            'statusBefore': run['statusBefore'] ?? '',
            'statusAfter': run['statusAfter'] ?? '',
            'outcome': run['outcome'] ?? 'pending',
            'summary': run['summary'] ?? '',
            'startedAt': run['startedAt'] ?? now.toIso8601String(),
            'completedAt': run['completedAt'],
          });
        }

        // Insert command logs
        for (final c
            in (manifest['command_logs'] as List? ?? [])
                .cast<Map<String, dynamic>>()) {
          final addr = c['targetAddress'] as String? ?? '';
          final targetId = addressToTargetId[addr] ?? 0;
          await txn.insert('command_logs', {
            'projectId': projectId,
            'targetId': targetId,
            'timestamp': c['timestamp'] ?? now.toIso8601String(),
            'command': c['command'] ?? '',
            'output': c['output'] ?? '',
            'exitCode': c['exitCode'] ?? 0,
            'vulnerabilityIndex': c['vulnerabilityIndex'],
          });
        }

        // Insert prompt logs
        for (final p
            in (manifest['prompt_logs'] as List? ?? [])
                .cast<Map<String, dynamic>>()) {
          final addr = p['targetAddress'] as String? ?? '';
          final targetId = addressToTargetId[addr] ?? 0;
          await txn.insert('prompt_logs', {
            'projectId': projectId,
            'targetId': targetId,
            'prompt': p['prompt'] as String? ?? '',
            'response': p['response'] as String? ?? '',
            'timestamp': DateTime.now().toIso8601String(),
          });
        }

        // Insert debug logs
        for (final d
            in (manifest['debug_logs'] as List? ?? [])
                .cast<Map<String, dynamic>>()) {
          final addr = d['targetAddress'] as String? ?? '';
          final targetId = addressToTargetId[addr] ?? 0;
          await txn.insert('debug_logs', {
            'projectId': projectId,
            'targetId': targetId,
            'message': d['message'] as String? ?? '',
            'timestamp': DateTime.now().toIso8601String(),
          });
        }

        // Insert credentials
        for (final c
            in (manifest['credentials'] as List? ?? [])
                .cast<Map<String, dynamic>>()) {
          await txn.insert('discovered_credentials', {
            'project_id': projectId,
            'service': c['service'] as String? ?? '',
            'host': c['host'] as String? ?? '',
            'username': c['username'] as String? ?? '',
            'secret': c['secret'] as String? ?? '',
            'secret_type': c['secret_type'] as String? ?? 'password',
            'source_vuln': c['source_vuln'] as String? ?? '',
            'discovered_at':
                DateTime.tryParse(
                  c['discovered_at'] as String? ?? '',
                )?.toIso8601String() ??
                now.toIso8601String(),
            'credential_source':
                c['credential_source'] as String? ?? 'extractedFromOutput',
          }, conflictAlgorithm: ConflictAlgorithm.ignore);
        }

        // Insert token usage
        for (final t
            in (manifest['token_usage'] as List? ?? [])
                .cast<Map<String, dynamic>>()) {
          final addr = t['target_id'] as String? ?? '';
          final targetId = addressToTargetId[addr] ?? 0;
          await txn.insert('token_usage', {
            'project_id': projectId,
            'target_id': targetId,
            'phase': t['phase'] as String? ?? '',
            'tokens_sent': t['tokens_sent'] as int? ?? 0,
            'tokens_received': t['tokens_received'] as int? ?? 0,
            'recorded_at': t['recorded_at'] as String? ?? now.toIso8601String(),
          });
        }

        // Insert executed commands
        for (final e
            in (manifest['executed_commands'] as List? ?? [])
                .cast<Map<String, dynamic>>()) {
          final addr = e['target_address'] as String? ?? '';
          final targetId = addressToTargetId[addr] ?? 0;
          await txn.insert('executed_commands', {
            'projectId': projectId,
            'targetId': targetId,
            'command_normalized': e['command_normalized'] as String? ?? '',
            'output': e['output'] as String? ?? '',
            'exit_code': e['exit_code'] as int? ?? -1,
            'executed_at': e['executed_at'] as String? ?? now.toIso8601String(),
          }, conflictAlgorithm: ConflictAlgorithm.ignore);
        }
      });

      final portableEvidenceEntries =
          (manifest['visual_evidence'] as List? ?? [])
              .cast<Map<String, dynamic>>();
      if (portableEvidenceEntries.isNotEmpty) {
        final restoredEvidence = await EvidencePortabilityService.restore(
          project: insertedProject,
          entries: portableEvidenceEntries,
          vulnerabilityIdMap: vulnerabilityIdMap,
          loadBytes: (archivePath) async {
            final entry = archiveFiles[archivePath];
            if (entry == null) {
              throw StateError('Portable evidence file is missing');
            }
            return entry;
          },
        );
        try {
          for (final artifact in restoredEvidence) {
            await DatabaseHelper.insertEvidenceArtifact(artifact);
          }
        } catch (_) {
          await db.delete(
            'evidence_artifacts',
            where: 'project_id = ?',
            whereArgs: [projectId],
          );
          for (final artifact in restoredEvidence) {
            await EvidenceStorageService.deleteEvidenceFile(
              project: insertedProject,
              artifact: artifact,
            );
          }
          rethrow;
        }
      }

      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text("Project '$projectName' imported successfully"),
          ),
        );
      }

      // Recompute hasResults from imported vulnerability data — the stored flag
      // may be false even when confirmed findings exist (e.g. exported before
      // execution completed, or flag was never persisted).
      final importedVulns = (manifest['vulnerabilities'] as List? ?? [])
          .cast<Map<String, dynamic>>();
      final hasConfirmed = importedVulns.any(
        (v) => (v['status'] as String? ?? '') == 'confirmed',
      );
      if (hasConfirmed && !insertedProject.hasResults) {
        await DatabaseHelper.updateProjectFlags(projectId, hasResults: true);
        return Project(
          id: insertedProject.id,
          name: insertedProject.name,
          folderPath: insertedProject.folderPath,
          createdAt: insertedProject.createdAt,
          lastOpenedAt: insertedProject.lastOpenedAt,
          scanComplete: insertedProject.scanComplete,
          analysisComplete: insertedProject.analysisComplete,
          hasResults: true,
          firstAnalysisAt: insertedProject.firstAnalysisAt,
          lastExecutionAt: insertedProject.lastExecutionAt,
          reportTitle: insertedProject.reportTitle,
          pentesterName: insertedProject.pentesterName,
          executiveSummary: insertedProject.executiveSummary,
          methodology: insertedProject.methodology,
          riskRatingModel: insertedProject.riskRatingModel,
          conclusion: insertedProject.conclusion,
          scope: insertedProject.scope,
          scopeExclusions: insertedProject.scopeExclusions,
          scopeNotes: insertedProject.scopeNotes,
        );
      }

      return insertedProject;
    } catch (error, stackTrace) {
      Object? rollbackError;
      final projectToRemove = rollbackProject;
      if (projectToRemove?.id != null) {
        try {
          await DatabaseHelper.deleteProject(projectToRemove!.id!);
        } catch (cleanupError) {
          rollbackError = cleanupError;
        }
      }
      final folderToRemove = rollbackFolderPath;
      if (folderToRemove != null) {
        try {
          final directory = Directory(folderToRemove);
          if (await directory.exists()) await directory.delete(recursive: true);
        } catch (cleanupError) {
          rollbackError ??= cleanupError;
        }
      }
      if (rollbackError != null) {
        throw StateError(
          'Project import failed and rollback was incomplete: $rollbackError',
        );
      }
      Error.throwWithStackTrace(error, stackTrace);
    }
  }

  static Future<String?> _promptRename(
    BuildContext context,
    String originalName,
  ) async {
    final controller = TextEditingController(text: '$originalName (imported)');
    return showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF1A1F3A),
        title: const Text(
          'Name Conflict',
          style: TextStyle(color: Color(0xFF00F5FF)),
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              "A project named '$originalName' already exists. Import as:",
              style: const TextStyle(color: Colors.white70, fontSize: 13),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: controller,
              autofocus: true,
              style: const TextStyle(color: Colors.white),
              decoration: InputDecoration(
                enabledBorder: OutlineInputBorder(
                  borderSide: BorderSide(
                    color: const Color(0xFF00F5FF).withValues(alpha: 0.4),
                  ),
                ),
                focusedBorder: const OutlineInputBorder(
                  borderSide: BorderSide(color: Color(0xFF00F5FF)),
                ),
                filled: true,
                fillColor: const Color(0xFF0A0E27),
              ),
              onSubmitted: (v) => Navigator.of(ctx).pop(v.trim()),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: const Text(
              'CANCEL',
              style: TextStyle(color: Colors.white54),
            ),
          ),
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(controller.text.trim()),
            child: const Text(
              'IMPORT',
              style: TextStyle(color: Color(0xFF00F5FF)),
            ),
          ),
        ],
      ),
    );
  }
}
