import 'dart:convert';

/// Durable candidate lifecycle. Only [planned] and [investigating] are active.
enum CandidateDisposition {
  planned,
  investigating,
  verifiedFinding,
  verifiedNegative,
  notApplicable,
  duplicateMerged,
  deferredByAuthorization,
  blockedMissingCredentials,
  blockedMfaOperatorAction,
  blockedConnectivity,
  blockedMissingAppliance,
  blockedScope,
  safeTestingLimitReached,
  technicallyInconclusiveBounded,
  pendingCustomerClarification,
  invalidHypothesis,
  toolingFailure;

  bool get isTerminal => this != planned && this != investigating;
}

enum ClosureReasonCode {
  directEvidenceVerified,
  rejectingEvidenceVerified,
  notApplicableToTarget,
  duplicateOfCanonicalRecord,
  authorizationRequired,
  authenticationRequired,
  manualMfaRequired,
  targetUnreachable,
  applianceUnavailable,
  outOfScope,
  safeRetryBudgetExhausted,
  safeToolBudgetExhausted,
  safeRequestBudgetExhausted,
  boundedMethodsExhausted,
  customerClarificationRequired,
  invalidOrUntestableClaim,
  requiredToolUnavailable,
}

enum WorkOwner { platform, operator, customer, joint }

/// Removes likely authentication material before closure metadata is persisted.
class ClosureSanitizer {
  const ClosureSanitizer._();

  static String text(Object? value, {int maxLength = 2000}) {
    var result = value?.toString() ?? '';
    const replacement = '[REDACTED]';
    result = result.replaceAll(
      RegExp(
        r'\b(authorization\s*:\s*(?:bearer|basic)\s+)[^\s,;]+',
        caseSensitive: false,
      ),
      r'$1[REDACTED]',
    );
    result = result.replaceAllMapped(
      RegExp(
        r'''\b(password|passwd|pwd|token|secret|api[_-]?key|cookie|session(?:id)?)\s*[:=]\s*[^\s,;]+''',
        caseSensitive: false,
      ),
      (match) => '${match.group(1)}=$replacement',
    );
    result = result.replaceAll(
      RegExp(
        r'\b(?:eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\b',
        caseSensitive: false,
      ),
      replacement,
    );
    result = result.replaceAll(RegExp(r'[\x00-\x08\x0B\x0C\x0E-\x1F]'), '');
    result = result.trim();
    return result.length <= maxLength
        ? result
        : '${result.substring(0, maxLength)}… [bounded]';
  }

  static List<String> list(Iterable<Object?> values) => values
      .map(text)
      .where((value) => value.isNotEmpty)
      .toList(growable: false);
}

class CandidateClosure {
  final int? id;
  final int vulnerabilityId;
  final int projectId;
  final CandidateDisposition disposition;
  final ClosureReasonCode reasonCode;
  final String explanation;
  final List<String> attemptedMethods;
  final List<String> successfulObservations;
  final List<String> failedObservations;
  final List<String> remainingPrerequisites;
  final String nextAction;
  final WorkOwner owner;
  final int retryBudget;
  final int toolBudget;
  final int requestBudget;
  final int retriesUsed;
  final int toolsUsed;
  final int requestsUsed;
  final String stoppingReason;
  final DateTime startedAt;
  final DateTime updatedAt;

  CandidateClosure({
    this.id,
    required this.vulnerabilityId,
    required this.projectId,
    required this.disposition,
    required this.reasonCode,
    required String explanation,
    List<String> attemptedMethods = const [],
    List<String> successfulObservations = const [],
    List<String> failedObservations = const [],
    List<String> remainingPrerequisites = const [],
    String nextAction = '',
    this.owner = WorkOwner.platform,
    this.retryBudget = 3,
    this.toolBudget = 3,
    this.requestBudget = 8,
    this.retriesUsed = 0,
    this.toolsUsed = 0,
    this.requestsUsed = 0,
    String stoppingReason = '',
    required this.startedAt,
    required this.updatedAt,
  }) : explanation = ClosureSanitizer.text(explanation),
       attemptedMethods = ClosureSanitizer.list(attemptedMethods),
       successfulObservations = ClosureSanitizer.list(successfulObservations),
       failedObservations = ClosureSanitizer.list(failedObservations),
       remainingPrerequisites = ClosureSanitizer.list(remainingPrerequisites),
       nextAction = ClosureSanitizer.text(nextAction),
       stoppingReason = ClosureSanitizer.text(stoppingReason);

  bool get isTerminal => disposition.isTerminal;
  bool get requiresFollowUp =>
      remainingPrerequisites.isNotEmpty || nextAction.isNotEmpty;

  CandidateClosure copyWith({
    CandidateDisposition? disposition,
    ClosureReasonCode? reasonCode,
    String? explanation,
    List<String>? attemptedMethods,
    List<String>? successfulObservations,
    List<String>? failedObservations,
    List<String>? remainingPrerequisites,
    String? nextAction,
    WorkOwner? owner,
    int? retryBudget,
    int? toolBudget,
    int? requestBudget,
    int? retriesUsed,
    int? toolsUsed,
    int? requestsUsed,
    String? stoppingReason,
    DateTime? updatedAt,
  }) => CandidateClosure(
    id: id,
    vulnerabilityId: vulnerabilityId,
    projectId: projectId,
    disposition: disposition ?? this.disposition,
    reasonCode: reasonCode ?? this.reasonCode,
    explanation: explanation ?? this.explanation,
    attemptedMethods: attemptedMethods ?? this.attemptedMethods,
    successfulObservations:
        successfulObservations ?? this.successfulObservations,
    failedObservations: failedObservations ?? this.failedObservations,
    remainingPrerequisites:
        remainingPrerequisites ?? this.remainingPrerequisites,
    nextAction: nextAction ?? this.nextAction,
    owner: owner ?? this.owner,
    retryBudget: retryBudget ?? this.retryBudget,
    toolBudget: toolBudget ?? this.toolBudget,
    requestBudget: requestBudget ?? this.requestBudget,
    retriesUsed: retriesUsed ?? this.retriesUsed,
    toolsUsed: toolsUsed ?? this.toolsUsed,
    requestsUsed: requestsUsed ?? this.requestsUsed,
    stoppingReason: stoppingReason ?? this.stoppingReason,
    startedAt: startedAt,
    updatedAt: updatedAt ?? this.updatedAt,
  );

  /// Reopens an exhausted candidate only after an explicit supervised action.
  /// Usage is retained so the ledger remains cumulative and auditable.
  CandidateClosure extendForSupervisedValidation({DateTime? now}) => copyWith(
    disposition: CandidateDisposition.planned,
    reasonCode: ClosureReasonCode.customerClarificationRequired,
    explanation:
        'An observing operator approved a bounded human-supervised validation extension.',
    nextAction:
        'Resume human-supervised validation with a materially different safe method.',
    owner: WorkOwner.operator,
    retryBudget: retryBudget < 5 ? 5 : retryBudget + 2,
    toolBudget: toolBudget < 8 ? 8 : toolBudget + 3,
    requestBudget: requestBudget < 30 ? 30 : requestBudget + 10,
    stoppingReason: '',
    updatedAt: (now ?? DateTime.now()).toUtc(),
  );

  Map<String, dynamic> toMap() => {
    'id': id,
    'vulnerability_id': vulnerabilityId,
    'project_id': projectId,
    'disposition': disposition.name,
    'reason_code': reasonCode.name,
    'explanation': explanation,
    'attempted_methods': jsonEncode(attemptedMethods),
    'successful_observations': jsonEncode(successfulObservations),
    'failed_observations': jsonEncode(failedObservations),
    'remaining_prerequisites': jsonEncode(remainingPrerequisites),
    'next_action': nextAction,
    'owner': owner.name,
    'retry_budget': retryBudget,
    'tool_budget': toolBudget,
    'request_budget': requestBudget,
    'retries_used': retriesUsed,
    'tools_used': toolsUsed,
    'requests_used': requestsUsed,
    'stopping_reason': stoppingReason,
    'started_at': startedAt.toUtc().toIso8601String(),
    'updated_at': updatedAt.toUtc().toIso8601String(),
  };

  factory CandidateClosure.fromMap(Map<String, dynamic> map) {
    List<String> decodeList(Object? value) {
      if (value is List) return value.map((item) => item.toString()).toList();
      try {
        return (jsonDecode(value?.toString() ?? '[]') as List)
            .map((item) => item.toString())
            .toList(growable: false);
      } catch (_) {
        return const [];
      }
    }

    T parseEnum<T extends Enum>(List<T> values, Object? raw, T fallback) =>
        values.firstWhere(
          (item) => item.name == raw?.toString(),
          orElse: () => fallback,
        );

    return CandidateClosure(
      id: (map['id'] as num?)?.toInt(),
      vulnerabilityId: (map['vulnerability_id'] as num?)?.toInt() ?? 0,
      projectId: (map['project_id'] as num?)?.toInt() ?? 0,
      disposition: parseEnum(
        CandidateDisposition.values,
        map['disposition'],
        CandidateDisposition.planned,
      ),
      reasonCode: parseEnum(
        ClosureReasonCode.values,
        map['reason_code'],
        ClosureReasonCode.customerClarificationRequired,
      ),
      explanation: map['explanation'],
      attemptedMethods: decodeList(map['attempted_methods']),
      successfulObservations: decodeList(map['successful_observations']),
      failedObservations: decodeList(map['failed_observations']),
      remainingPrerequisites: decodeList(map['remaining_prerequisites']),
      nextAction: map['next_action']?.toString() ?? '',
      owner: parseEnum(WorkOwner.values, map['owner'], WorkOwner.platform),
      retryBudget: (map['retry_budget'] as num?)?.toInt() ?? 3,
      toolBudget: (map['tool_budget'] as num?)?.toInt() ?? 3,
      requestBudget: (map['request_budget'] as num?)?.toInt() ?? 8,
      retriesUsed: (map['retries_used'] as num?)?.toInt() ?? 0,
      toolsUsed: (map['tools_used'] as num?)?.toInt() ?? 0,
      requestsUsed: (map['requests_used'] as num?)?.toInt() ?? 0,
      stoppingReason: map['stopping_reason']?.toString() ?? '',
      startedAt:
          DateTime.tryParse(map['started_at']?.toString() ?? '')?.toUtc() ??
          DateTime.fromMillisecondsSinceEpoch(0, isUtc: true),
      updatedAt:
          DateTime.tryParse(map['updated_at']?.toString() ?? '')?.toUtc() ??
          DateTime.fromMillisecondsSinceEpoch(0, isUtc: true),
    );
  }
}
