import 'dart:convert';

import 'candidate_closure.dart';

enum HumanValidationStatus {
  waitingAuthorization,
  waitingCustomer,
  ready,
  inProgress,
  completed,
  declined,
}

/// Non-secret coordination card for tests that cannot safely be automated.
class HumanValidationWorkItem {
  final String id;
  final int projectId;
  final int vulnerabilityId;
  final String title;
  final String authorizationRequired;
  final List<String> evidenceRequested;
  final String safetyNotes;
  final WorkOwner owner;
  final HumanValidationStatus status;
  final List<String> evidenceReferences;
  final DateTime createdAt;
  final DateTime updatedAt;

  HumanValidationWorkItem({
    required this.id,
    required this.projectId,
    required this.vulnerabilityId,
    required String title,
    required String authorizationRequired,
    List<String> evidenceRequested = const [],
    required String safetyNotes,
    required this.owner,
    required this.status,
    List<String> evidenceReferences = const [],
    required this.createdAt,
    required this.updatedAt,
  }) : title = ClosureSanitizer.text(title, maxLength: 500),
       authorizationRequired = ClosureSanitizer.text(authorizationRequired),
       evidenceRequested = ClosureSanitizer.list(evidenceRequested),
       safetyNotes = ClosureSanitizer.text(safetyNotes),
       evidenceReferences = ClosureSanitizer.list(evidenceReferences);

  HumanValidationWorkItem copyWith({
    HumanValidationStatus? status,
    List<String>? evidenceReferences,
    DateTime? updatedAt,
  }) => HumanValidationWorkItem(
    id: id,
    projectId: projectId,
    vulnerabilityId: vulnerabilityId,
    title: title,
    authorizationRequired: authorizationRequired,
    evidenceRequested: evidenceRequested,
    safetyNotes: safetyNotes,
    owner: owner,
    status: status ?? this.status,
    evidenceReferences: evidenceReferences ?? this.evidenceReferences,
    createdAt: createdAt,
    updatedAt: updatedAt ?? this.updatedAt,
  );

  Map<String, dynamic> toMap() => {
    'id': id,
    'project_id': projectId,
    'vulnerability_id': vulnerabilityId,
    'title': title,
    'authorization_required': authorizationRequired,
    'evidence_requested': jsonEncode(evidenceRequested),
    'safety_notes': safetyNotes,
    'owner': owner.name,
    'status': status.name,
    'evidence_references': jsonEncode(evidenceReferences),
    'created_at': createdAt.toUtc().toIso8601String(),
    'updated_at': updatedAt.toUtc().toIso8601String(),
  };

  factory HumanValidationWorkItem.fromMap(Map<String, dynamic> map) {
    List<String> list(Object? value) {
      try {
        return (jsonDecode(value?.toString() ?? '[]') as List)
            .map((item) => item.toString())
            .toList(growable: false);
      } catch (_) {
        return const [];
      }
    }

    return HumanValidationWorkItem(
      id: map['id']?.toString() ?? '',
      projectId: (map['project_id'] as num?)?.toInt() ?? 0,
      vulnerabilityId: (map['vulnerability_id'] as num?)?.toInt() ?? 0,
      title: map['title']?.toString() ?? '',
      authorizationRequired: map['authorization_required']?.toString() ?? '',
      evidenceRequested: list(map['evidence_requested']),
      safetyNotes: map['safety_notes']?.toString() ?? '',
      owner: WorkOwner.values.firstWhere(
        (item) => item.name == map['owner'],
        orElse: () => WorkOwner.operator,
      ),
      status: HumanValidationStatus.values.firstWhere(
        (item) => item.name == map['status'],
        orElse: () => HumanValidationStatus.waitingCustomer,
      ),
      evidenceReferences: list(map['evidence_references']),
      createdAt:
          DateTime.tryParse(map['created_at']?.toString() ?? '')?.toUtc() ??
          DateTime.fromMillisecondsSinceEpoch(0, isUtc: true),
      updatedAt:
          DateTime.tryParse(map['updated_at']?.toString() ?? '')?.toUtc() ??
          DateTime.fromMillisecondsSinceEpoch(0, isUtc: true),
    );
  }
}
