import 'dart:async';
import '../models/llm_settings.dart';
import '../services/command_executor.dart';
import '../services/llm_service.dart';
import 'json_parser.dart';

/// Result of a pre-flight command validation check.
class CommandValidationResult {
  /// True if the command passed all checks (or was corrected).
  final bool isValid;

  /// True only for the non-script file execution case — caller must skip the command entirely.
  final bool shouldHardBlock;

  /// Non-null when Tier 1 or Tier 2 produced a corrected version of the command.
  final String? correctedCommand;

  /// Human-readable explanation for the debug log.
  final String reason;

  const CommandValidationResult({
    required this.isValid,
    this.shouldHardBlock = false,
    this.correctedCommand,
    required this.reason,
  });

  /// Convenience: passed with no changes.
  const CommandValidationResult.pass()
    : isValid = true,
      shouldHardBlock = false,
      correctedCommand = null,
      reason = '';
}

/// Pre-flight command validator.
///
/// Runs two tiers of checks before a command is sent to the shell:
/// - Tier 1: static checks (zero token cost, always runs)
/// - Tier 2: LLM-assisted syntax validation (selective, cached, best-effort)
class CommandValidator {
  // ---------------------------------------------------------------------------
  // High-risk tool set — Tier 2 LLM validation fires only for these tools.
  // These have complex, version-sensitive flag syntax where the LLM frequently
  // makes errors. Update this list when new complex tools are added.
  // ---------------------------------------------------------------------------
  static const _highRiskTools = {
    'nmap',
    'sqlmap',
    'gobuster',
    'ffuf',
    'hydra',
    'nuclei',
    'metasploit',
    'msfconsole',
    'testssl.sh',
    'testssl',
    'enum4linux',
    'enum4linux-ng',
    'crackmapexec',
    'netexec',
    'wpscan',
    'feroxbuster',
    'nikto',
    'wfuzz',
    'john',
    'hashcat',
    'responder',
    'smbclient',
    'rpcclient',
    'ldapsearch',
    'kerbrute',
  };

  // Known script file extensions — bash/sh executing these is legitimate.
  static const _scriptExtensions = {
    '.sh',
    '.bash',
    '.zsh',
    '.py',
    '.rb',
    '.pl',
    '.ps1',
    '.lua',
  };

  // Known wordlist / data directory patterns — executing files from these is never valid.
  static const _wordlistDirPatterns = [
    '/usr/share/wordlists',
    '/usr/share/dirb',
    '/usr/share/dirbuster',
    '/usr/share/seclists',
    '/opt/seclists',
    '/usr/share/wfuzz',
    '/usr/share/nmap',
    'wordlist',
    'seclists',
  ];

  // Known bare-word flag keywords — these should always have a dash prefix.
  static const _bareWordFlagKeywords = {
    'verbose',
    'output',
    'port',
    'host',
    'target',
    'wordlist',
    'threads',
  };

  /// Validate [command] before execution.
  ///
  /// Runs Tier 1 (static) always. Runs Tier 2 (LLM) only for high-risk tools
  /// when Tier 1 passes without a hard block or correction.
  ///
  /// Never throws — all errors are caught and result in a pass-through.
  static Future<CommandValidationResult> validate(
    String command,
    LLMSettings settings,
    LLMService llmService,
  ) async {
    // --- Tier 1 ---
    final tier1 = _runTier1(command);
    if (tier1 != null) return tier1;

    // --- Tier 2 (selective) ---
    final primaryTool = _extractPrimaryTool(command);
    if (primaryTool != null &&
        _highRiskTools.contains(primaryTool.toLowerCase())) {
      final tier2 = await _runTier2(command, primaryTool, settings, llmService);
      final corrected = tier2.correctedCommand;
      if (corrected != null) {
        // An LLM-generated correction is untrusted input. Re-run every
        // deterministic Tier-1 boundary so a safe proposal cannot be changed
        // into a destructive command after the initial policy check.
        final correctedTier1 = _runTier1(corrected);
        if (correctedTier1?.shouldHardBlock == true) {
          return correctedTier1!;
        }
        if (correctedTier1?.correctedCommand != null) {
          return CommandValidationResult(
            isValid: true,
            correctedCommand: correctedTier1!.correctedCommand,
            reason: '${tier2.reason} ${correctedTier1.reason}'.trim(),
          );
        }
      }
      return tier2;
    }

    return const CommandValidationResult.pass();
  }

  /// Deterministic validation entry point for tests and non-LLM callers.
  static CommandValidationResult validateMandatoryPolicy(String command) {
    return _runTier1(command) ?? const CommandValidationResult.pass();
  }

  // ---------------------------------------------------------------------------
  // Tier 1 — Static checks
  // ---------------------------------------------------------------------------

  /// Run all static checks. Returns a result if any check fires, null if all pass.
  static CommandValidationResult? _runTier1(String command) {
    // Mandatory appliance policy: assessment execution is evidence-focused,
    // non-destructive, and must not perform denial-of-service testing.
    final safetyBlock = _checkNonDestructivePolicy(command);
    if (safetyBlock != null) return safetyBlock;

    // 6.3a — Non-script file execution (HARD BLOCK)
    final nonScriptBlock = _checkNonScriptExecution(command);
    if (nonScriptBlock != null) return nonScriptBlock;

    // 6.3b — Dangerous shell patterns (HARD BLOCK)
    final dangerousBlock = _checkDangerousShellPatterns(command);
    if (dangerousBlock != null) return dangerousBlock;

    // 6.3c — WSL path translation (correction, not block)
    final wslCorrection = _checkWslPaths(command);
    if (wslCorrection != null) return wslCorrection;

    // 6.3d — Bare-word flag detection (soft warning, pass through)
    _checkBareWordFlags(
      command,
    ); // side-effect: logs only, no return value needed

    return null;
  }

  static final List<MapEntry<RegExp, String>> _nonDestructiveBlocks = [
    MapEntry(
      RegExp(
        r'\b(?:hping3?|nping)\b.*(?:--flood|--rate\s+[1-9]\d{3,})',
        caseSensitive: false,
      ),
      'denial-of-service or packet flooding is prohibited',
    ),
    MapEntry(
      RegExp(
        r'\b(?:slowloris|slowhttptest|goldeneye|siege|wrk|ab|hey|vegeta|bombardier)\b',
        caseSensitive: false,
      ),
      'load generation and denial-of-service tools are prohibited',
    ),
    MapEntry(
      RegExp(
        r'\bnmap\b.*--script(?:=|\s+)[^\n;&|]*(?:\bdos\b|intrusive|exploit|brute|flood|slowloris)',
        caseSensitive: false,
      ),
      'denial-of-service, intrusive, exploit, and brute-force NSE script categories are prohibited',
    ),
    MapEntry(
      RegExp(r'\b(?:shutdown|reboot|poweroff|halt)\b', caseSensitive: false),
      'service or host disruption is prohibited',
    ),
    MapEntry(
      RegExp(
        r'\b(?:systemctl\s+(?:stop|restart|disable|mask)|service\s+\S+\s+(?:stop|restart))\b',
        caseSensitive: false,
      ),
      'service modification is prohibited',
    ),
    MapEntry(
      RegExp(r'\b(?:ldapmodify|snmpset)\b', caseSensitive: false),
      'remote directory or device configuration modification is prohibited',
    ),
    MapEntry(
      RegExp(
        r'\b(?:useradd|adduser|userdel|groupadd|passwd)\b|\bnet\s+user\b.*\s/add\b',
        caseSensitive: false,
      ),
      'account creation or modification is prohibited',
    ),
    MapEntry(
      RegExp(
        r'\b(?:schtasks\b.*\s/create\b|sc(?:\.exe)?\s+create\b|crontab\s+-)',
        caseSensitive: false,
      ),
      'persistence creation is prohibited',
    ),
    MapEntry(
      RegExp(
        r'\b(?:hydra|medusa|patator|hashcat|john)\b|\bkerbrute\b.*(?:passwordspray|bruteuser|bruteforce)|\bpassword\s*spray(?:ing)?\b',
        caseSensitive: false,
      ),
      'password spraying, brute force, and credential cracking are prohibited',
    ),
    MapEntry(
      RegExp(
        r'\b(?:secretsdump(?:\.py)?|mimikatz|procdump)\b|/etc/shadow\b|\bntds\.dit\b|\blsass(?:\.exe|\.dmp)?\b',
        caseSensitive: false,
      ),
      'credential dumping or sensitive credential-file extraction is prohibited',
    ),
    MapEntry(
      RegExp(
        r'\bnc(?:at)?\b[^\n;&|]*(?:\s-e\s|\s-[A-Za-z]*l[A-Za-z]*\b)|\bsocat\b[^\n;&|]*(?:listen|exec:)|/dev/tcp/|\bbash\s+-i\b|\bpython\d*(?:\.\d+)?\s+-m\s+http\.server\b',
        caseSensitive: false,
      ),
      'reverse or bind shells are prohibited; use a harmless command marker instead',
    ),
    MapEntry(
      RegExp(
        r'\bmsfconsole\b.*(?:set\s+payload|meterpreter|\bexploit\s*(?:;|$))',
        caseSensitive: false,
      ),
      'full exploit payloads and interactive sessions are prohibited; use check or scanner modules',
    ),
    MapEntry(
      RegExp(
        r'\bcurl\b.*(?:-T\s|--upload-file\b|(?:-X|--request)(?:=|\s*)["\x27]?(?:PUT|POST|PATCH|DELETE)\b|(?:^|\s)-(?:d|F)(?:\s|["\x27])|--data(?:-raw|-binary|-urlencode)?\b|--form\b)|\bwget\b.*(?:--post-(?:data|file)\b|--method(?:=|\s+)["\x27]?(?:PUT|POST|PATCH|DELETE)\b)|\bscp\b\s+\S+\s+\S+@[^:]+:|\brsync\b.*\S+@[^:]+:',
        caseSensitive: false,
      ),
      'target uploads and state-changing HTTP methods are prohibited',
    ),
    MapEntry(
      RegExp(
        r'\brequests\.(?:post|put|patch|delete)\s*\(|\brequests\.request\s*\(\s*["\x27](?:POST|PUT|PATCH|DELETE)\b|\burllib\.request\.Request\s*\([^\n]*(?:method\s*=\s*["\x27](?:POST|PUT|PATCH|DELETE)|data\s*=)|\bInvoke-(?:WebRequest|RestMethod)\b.*-Method\s+["\x27]?(?:POST|PUT|PATCH|DELETE)\b|\bhttp\b\s+(?:POST|PUT|PATCH|DELETE)\s+',
        caseSensitive: false,
      ),
      'state-changing HTTP requests are prohibited',
    ),
    MapEntry(
      RegExp(
        r'\bredis-cli\b.*\b(?:set|del|flushall|flushdb|config\s+set)\b|\bsmbclient\b.*\s-c\s+["\x27][^"\x27]*(?:put|del|mkdir|rmdir)\b|\bftp\b.*\b(?:put|delete|mkdir|rmdir)\b',
        caseSensitive: false,
      ),
      'remote data or configuration modification is prohibited',
    ),
    MapEntry(
      RegExp(
        r'\bsqlmap\b.*(?:--os-shell|--os-cmd|--file-write|--file-dest|--dump|--passwords)',
        caseSensitive: false,
      ),
      'database extraction, file writes, and operating-system payloads are prohibited',
    ),
    MapEntry(
      RegExp(
        r'\b(?:mysql|psql|sqlcmd)\b.*\b(?:insert|update|delete|drop|alter|truncate)\b',
        caseSensitive: false,
      ),
      'database mutation is prohibited',
    ),
  ];

  static CommandValidationResult? _checkNonDestructivePolicy(String command) {
    for (final rule in _nonDestructiveBlocks) {
      if (!rule.key.hasMatch(command)) continue;
      return CommandValidationResult(
        isValid: false,
        shouldHardBlock: true,
        reason:
            'SAFETY BLOCK: ${rule.value}. Use a targeted read-only proof technique.',
      );
    }
    return null;
  }

  /// 6.3a — Detect bash/sh executing a non-script file (the wordlist-as-script bug).
  static CommandValidationResult? _checkNonScriptExecution(String command) {
    final cmd = command.trim();

    // Match: bash <path> or sh <path> where <path> is not a quoted -c string
    // Patterns: `bash /some/path`, `sh /some/path`, `bash -x /some/path`, etc.
    final shellExecPattern = RegExp(
      r'\b(bash|sh)\s+(?:-[a-zA-Z]+\s+)*([^\s"&|;]+)',
      caseSensitive: false,
    );

    for (final match in shellExecPattern.allMatches(cmd)) {
      final arg = match.group(2) ?? '';

      // Skip if it's a -c flag (quoted inline command)
      if (arg == '-c') continue;

      // Skip if it looks like a flag (starts with -)
      if (arg.startsWith('-')) continue;

      // Only check if it looks like a file path
      if (!arg.contains('/') && !arg.contains('\\')) continue;

      // Allow known script extensions
      final lower = arg.toLowerCase();
      if (_scriptExtensions.any((ext) => lower.endsWith(ext))) continue;

      // Hard block if it matches a wordlist directory pattern
      final isWordlistPath = _wordlistDirPatterns.any((p) => lower.contains(p));
      if (isWordlistPath ||
          lower.endsWith('.txt') ||
          lower.endsWith('.lst') ||
          lower.endsWith('.log')) {
        return CommandValidationResult(
          isValid: false,
          shouldHardBlock: true,
          reason:
              'HARD BLOCK: command attempts to execute non-script file as shell script: $arg. '
              'Do not execute wordlist or text files with bash/sh. '
              'Use the appropriate tool (gobuster, ffuf, dirb) with the wordlist as an argument instead.',
        );
      }
    }

    // Also catch: `source <path>` or `. <path>` for non-config files
    final sourcePattern = RegExp(
      r'\b(source|\.)\s+([^\s"&|;]+)',
      caseSensitive: false,
    );
    for (final match in sourcePattern.allMatches(cmd)) {
      final arg = match.group(2) ?? '';
      final lower = arg.toLowerCase();
      // Allow known shell config files
      if (lower.contains('.bashrc') ||
          lower.contains('.profile') ||
          lower.contains('.zshrc') ||
          lower.contains('.env') ||
          _scriptExtensions.any((ext) => lower.endsWith(ext))) {
        continue;
      }
      if (lower.endsWith('.txt') ||
          lower.endsWith('.lst') ||
          _wordlistDirPatterns.any((p) => lower.contains(p))) {
        return CommandValidationResult(
          isValid: false,
          shouldHardBlock: true,
          reason:
              'HARD BLOCK: command sources a non-script file: $arg. '
              'Do not source wordlist or text files.',
        );
      }
    }

    return null;
  }

  /// 6.3b — Detect dangerous shell patterns beyond the existing blocklist.
  static CommandValidationResult? _checkDangerousShellPatterns(String command) {
    final lower = command.toLowerCase();

    // cat <file> | bash  or  cat <file> | sh
    if (RegExp(r'\bcat\s+\S+\s*\|\s*(bash|sh)\b').hasMatch(lower)) {
      return CommandValidationResult(
        isValid: false,
        shouldHardBlock: true,
        reason:
            'HARD BLOCK: piping file contents into bash/sh is not permitted in the testing loop. '
            'Execute scripts directly instead.',
      );
    }

    // curl <url> | bash  or  wget -O- <url> | bash
    if (RegExp(r'\b(curl|wget)\b.*\|\s*(bash|sh)\b').hasMatch(lower)) {
      return CommandValidationResult(
        isValid: false,
        shouldHardBlock: true,
        reason:
            'HARD BLOCK: piping remote content into bash/sh is not permitted. '
            'Download the script first, inspect it, then execute it explicitly.',
      );
    }

    return null;
  }

  /// 6.3c — Detect Windows-style paths in WSL commands and translate them.
  static CommandValidationResult? _checkWslPaths(String command) {
    // Only relevant when running under WSL
    // We check synchronously using a cached flag pattern — actual WSL check
    // is async so we use a heuristic: if the command contains a Windows-style
    // absolute path (C:\...) it's almost certainly wrong in a WSL context.
    final windowsPathPattern = RegExp(
      r'([A-Za-z]):\\([^\s"]+)',
      caseSensitive: false,
    );
    if (!windowsPathPattern.hasMatch(command)) return null;

    var corrected = command;
    final matches = windowsPathPattern.allMatches(command).toList();

    for (final match in matches) {
      final driveLetter = match.group(1)!.toLowerCase();
      final rest = match.group(2)!.replaceAll('\\', '/');
      final wslPath = '/mnt/$driveLetter/$rest';
      corrected = corrected.replaceFirst(match.group(0)!, wslPath);
    }

    if (corrected != command) {
      return CommandValidationResult(
        isValid: true,
        correctedCommand: corrected,
        reason:
            'WSL path translation applied: Windows-style paths converted to /mnt/ equivalents.',
      );
    }

    return null;
  }

  /// 6.3d — Detect bare-word flags (soft check, no block — just returns a note).
  /// Returns null always; the caller can log the reason if non-empty.
  static void _checkBareWordFlags(String command) {
    final tokens = command.split(RegExp(r'\s+'));
    if (tokens.isEmpty) return;

    // Skip the tool name itself (first token)
    for (int i = 1; i < tokens.length; i++) {
      final token = tokens[i].toLowerCase();
      if (_bareWordFlagKeywords.contains(token)) {
        // Check if the previous token was a flag (starts with -)
        final prev = i > 0 ? tokens[i - 1] : '';
        if (!prev.startsWith('-')) {
          // Bare-word flag detected — logged by caller via debug log
          // This is a soft warning only; we don't block or correct
        }
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Tier 2 — LLM-assisted validation
  // ---------------------------------------------------------------------------

  /// Run LLM-assisted validation for a high-risk tool command.
  ///
  /// Uses cached [ToolUsageInfo] as context. Times out after 20 seconds.
  /// On any failure, passes the original command through.
  static Future<CommandValidationResult> _runTier2(
    String command,
    String tool,
    LLMSettings settings,
    LLMService llmService,
  ) async {
    try {
      final toolInfo = await CommandExecutor.getToolUsageInfo(
        tool,
        settings,
        llmService,
      ).timeout(const Duration(seconds: 15));
      var toolRef = CommandExecutor.formatToolUsageForPrompt(toolInfo);

      // Phase 10: For nuclei, append runtime-detected flag summary to toolRef
      // so corrections use the exact flags of the installed version.
      if (tool == 'nuclei') {
        try {
          final flagCheck = await CommandExecutor.executeCommand(
            'nuclei -h 2>&1 | grep -E "^\\s+-(t|id|template-id|tags|severity)" | head -10',
            false,
          ).timeout(const Duration(seconds: 8));
          final flagOutput = (flagCheck['output'] ?? '').toString().trim();
          if (flagOutput.isNotEmpty) {
            toolRef +=
                '\n\nACTUAL INSTALLED FLAGS (from nuclei -h):\n$flagOutput\n'
                'Use ONLY these exact flag names. Do not invent flags not shown above.';
          }
        } catch (_) {}
      }

      final osInfo = await CommandExecutor.getOsInfo();

      // 6.4b — Build the validation prompt
      final prompt =
          '''You are validating a shell command before execution on $osInfo.

TOOL REFERENCE:
$toolRef

COMMAND TO VALIDATE:
$command

Is this command syntactically valid for this tool and OS? Check:
1. Flag names are correct (case-sensitive, correct prefix)
2. Required arguments are present
3. No conflicting flags
4. File paths are plausible for this OS
5. No obvious logic errors (e.g. output file same as input file)

Respond with JSON only:
{
  "valid": true,
  "issues": [],
  "corrected_command": null
}

If invalid:
{
  "valid": false,
  "issues": ["specific problem 1", "specific problem 2"],
  "corrected_command": "corrected version of the command"
}

Respond ONLY with valid JSON. No markdown, no explanation outside the JSON.''';

      final response = await llmService
          .sendMessage(settings, prompt)
          .timeout(const Duration(seconds: 20));

      // 6.4c — Parse and act on the response
      final parsed = JsonParser.tryParseJson(response);
      if (parsed == null) {
        return const CommandValidationResult.pass();
      }

      final isValid = parsed['valid'] == true;
      final issues = (parsed['issues'] as List?)?.cast<String>() ?? [];
      final corrected = parsed['corrected_command']?.toString();

      if (isValid) {
        return const CommandValidationResult.pass();
      }

      // Invalid — substitute corrected command if provided
      if (corrected != null && corrected.isNotEmpty && corrected != 'null') {
        return CommandValidationResult(
          isValid: true, // corrected command is valid to run
          correctedCommand: corrected,
          reason:
              '[PRE-FLIGHT CORRECTION] $tool command corrected. '
              'Issues: ${issues.join(', ')}. '
              'Original: $command → Corrected: $corrected',
        );
      }

      // Invalid but no correction — log and pass through (don't stall the loop)
      return CommandValidationResult(
        isValid: true,
        reason:
            '[PRE-FLIGHT WARNING] $tool command may have issues: ${issues.join(', ')}. '
            'Proceeding with original command.',
      );
    } on TimeoutException {
      return CommandValidationResult(
        isValid: true,
        reason: '[PRE-FLIGHT] Validation skipped for: $tool (timeout)',
      );
    } catch (e) {
      return CommandValidationResult(
        isValid: true,
        reason: '[PRE-FLIGHT] Validation skipped for: $tool (error: $e)',
      );
    }
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  /// Extract the primary tool name from a command string.
  static String? _extractPrimaryTool(String command) {
    final trimmed = command.trim();
    if (trimmed.isEmpty) return null;
    // Handle sudo prefix
    final withoutSudo = trimmed.startsWith('sudo ')
        ? trimmed.substring(5).trim()
        : trimmed;
    return withoutSudo.split(RegExp(r'\s+')).first.toLowerCase();
  }
}
