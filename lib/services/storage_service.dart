import 'dart:io';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';

class StorageService {
  static String? _customBasePath;

  static void setCustomBasePath(String? path) {
    _customBasePath = path;
  }

  static Future<String> getBasePath() async {
    if (_customBasePath != null && _customBasePath!.isNotEmpty) {
      return _customBasePath!;
    }
    final docs = await getApplicationDocumentsDirectory();
    return p.join(docs.path, 'LLMtary');
  }

  static Future<String> getProjectPath(String projectName) async {
    final safeName = validateProjectName(projectName);
    final base = await getBasePath();
    final path = p.join(base, safeName);
    await Directory(path).create(recursive: true);
    return path;
  }

  static Future<String> createNewProjectPath(String projectName) async {
    final safeName = validateProjectName(projectName);
    final base = p.normalize(p.absolute(await getBasePath()));
    await Directory(base).create(recursive: true);
    final path = p.normalize(p.join(base, safeName));
    if (!p.isWithin(base, path)) {
      throw const FormatException('Project path escaped local storage.');
    }
    final directory = Directory(path);
    if (await directory.exists()) {
      throw FileSystemException('Project directory already exists', path);
    }
    await directory.create();
    return path;
  }

  static Future<String> getTargetPath(
    String projectName,
    String address,
  ) async {
    final project = await getProjectPath(projectName);
    final safe = safeTargetDirectoryName(address);
    final path = p.normalize(p.join(project, safe));
    if (!p.isWithin(p.normalize(project), path)) {
      throw const FormatException('Target path escaped project storage.');
    }
    await Directory(path).create(recursive: true);
    return path;
  }

  /// Converts a native path to the form usable inside the shell that will
  /// actually execute commands (WSL bash on Windows, native path elsewhere).
  static String toShellPath(String nativePath) {
    if (!Platform.isWindows) return nativePath;
    // Convert Windows path to WSL mount path:
    // C:\Users\foo\bar  ->  /mnt/c/Users/foo/bar
    final normalized = nativePath.replaceAll('\\', '/');
    final match = RegExp(r'^([A-Za-z]):(.*)').firstMatch(normalized);
    if (match == null) return normalized;
    final drive = match.group(1)!.toLowerCase();
    final rest = match.group(2)!;
    return '/mnt/$drive$rest';
  }

  static Future<List<String>> listProjects() async {
    final base = await getBasePath();
    final dir = Directory(base);
    if (!await dir.exists()) return [];
    return dir
        .listSync()
        .whereType<Directory>()
        .map((d) => p.basename(d.path))
        .toList();
  }

  static Future<void> deleteProjectFolder(String projectName) async {
    final path = p.join(await getBasePath(), validateProjectName(projectName));
    final dir = Directory(path);
    if (await dir.exists()) await dir.delete(recursive: true);
  }

  static String validateProjectName(String projectName) {
    if (projectName.isEmpty ||
        projectName.length > 128 ||
        projectName.trim() != projectName ||
        projectName == '.' ||
        projectName == '..' ||
        projectName.contains('/') ||
        projectName.contains('\\') ||
        RegExp(r'[\x00-\x1f\x7f]').hasMatch(projectName) ||
        p.isAbsolute(projectName)) {
      throw const FormatException(
        'Project name is not safe for local storage.',
      );
    }
    return projectName;
  }

  static String safeTargetDirectoryName(String address) {
    var safe = address.replaceAll(RegExp(r'[^\w\.\-]'), '_');
    if (safe.isEmpty || safe == '.' || safe == '..' || safe != address) {
      var hash = 0x811c9dc5;
      for (final byte in address.codeUnits) {
        hash = ((hash ^ byte) * 0x01000193) & 0xffffffff;
      }
      final base = safe.isEmpty || safe == '.' || safe == '..'
          ? 'target'
          : safe;
      safe = '$base-${hash.toRadixString(16).padLeft(8, '0')}';
    }
    return safe;
  }

  static String validatePortableFileName(String fileName) {
    if (fileName.isEmpty ||
        fileName == '.' ||
        fileName == '..' ||
        fileName.contains('/') ||
        fileName.contains('\\') ||
        p.basename(fileName) != fileName) {
      throw const FormatException('Portable filename is unsafe.');
    }
    return fileName;
  }

  static String portableArchiveFileName(String fileName) {
    try {
      return validatePortableFileName(fileName);
    } on FormatException {
      var hash = 0x811c9dc5;
      for (final unit in fileName.codeUnits) {
        hash ^= unit;
        hash = (hash * 0x01000193) & 0xffffffff;
      }
      var safe = fileName.replaceAll(RegExp(r'[^A-Za-z0-9._-]'), '_');
      safe = safe.replaceFirst(RegExp(r'^\.+'), '');
      if (safe.isEmpty) safe = 'file';
      if (safe.length > 180) safe = safe.substring(0, 180);
      return validatePortableFileName(
        'encoded-${hash.toRadixString(16).padLeft(8, '0')}-$safe',
      );
    }
  }
}
