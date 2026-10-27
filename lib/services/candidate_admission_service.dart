import '../models/vulnerability.dart';

enum CandidateRecordKind {
  hypothesis,
  observation,
  attackPath,
  invalidHypothesis,
}

class CandidateAdmissionDecision {
  final bool accepted;
  final CandidateRecordKind recordKind;
  final String reason;
  const CandidateAdmissionDecision(this.accepted, this.recordKind, this.reason);
}

/// Deterministic gate that keeps observations and prose out of the test queue.
class CandidateAdmissionService {
  const CandidateAdmissionService._();

  static CandidateAdmissionDecision classify(Vulnerability candidate) {
    final text = '${candidate.problem} ${candidate.vulnerabilityType}'
        .toLowerCase()
        .trim();
    if (text.isEmpty ||
        text.contains('unknown vulnerability') ||
        text == 'unknown' ||
        text.contains('pending attack chain')) {
      return const CandidateAdmissionDecision(
        false,
        CandidateRecordKind.invalidHypothesis,
        'The record does not contain a specific, testable security claim.',
      );
    }
    const observationTerms = [
      'protocol detected',
      'service detected',
      'service exposure',
      'fingerprinting',
      'certificate transparency data',
      'dns service',
      'safety advisory',
    ];
    if (observationTerms.any(text.contains)) {
      return const CandidateAdmissionDecision(
        false,
        CandidateRecordKind.observation,
        'The record is contextual exposure information, not a vulnerability claim.',
      );
    }
    if (text.contains('attack chain') || text.contains('combined path')) {
      return const CandidateAdmissionDecision(
        false,
        CandidateRecordKind.attackPath,
        'Attack paths must be derived from verified findings.',
      );
    }
    return const CandidateAdmissionDecision(
      true,
      CandidateRecordKind.hypothesis,
      'Specific hypothesis admitted for bounded verification.',
    );
  }
}
