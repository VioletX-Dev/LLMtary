import 'dart:io';

class BrowserRuntimeConfiguration {
  static const defaultExecutable = '/usr/bin/chromium';
  static const approvedExecutables = <String>{
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
    '/snap/bin/chromium',
  };

  static String resolve({File? configFile}) {
    final file = configFile ?? File('/etc/llmtary/browser-runtime.conf');
    try {
      if (FileSystemEntity.typeSync(file.path, followLinks: false) !=
          FileSystemEntityType.file) {
        return defaultExecutable;
      }
      final configStat = file.statSync();
      const groupOrOtherWriteBits = 0x12;
      if ((configStat.mode & groupOrOtherWriteBits) != 0) {
        return defaultExecutable;
      }
      if (file.lengthSync() > 512) return defaultExecutable;
      final lines = file.readAsLinesSync();
      if (lines.length != 1) return defaultExecutable;
      const prefix = 'CHROMIUM_EXECUTABLE=';
      final line = lines.single.trim();
      if (!line.startsWith(prefix)) return defaultExecutable;
      final executable = line.substring(prefix.length);
      return approvedExecutables.contains(executable)
          ? executable
          : defaultExecutable;
    } on FileSystemException {
      return defaultExecutable;
    }
  }

  static bool isUsable(String executable) {
    if (!approvedExecutables.contains(executable)) return false;
    try {
      final stat = FileStat.statSync(executable);
      const anyExecuteBit = 0x49;
      return stat.type == FileSystemEntityType.file &&
          (stat.mode & anyExecuteBit) != 0;
    } on FileSystemException {
      return false;
    }
  }
}
