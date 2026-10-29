import 'dart:io';

class SupervisedValidationAuthorization {
  final String engagementReference;
  final String observingOperator;
  final String sourceAddress;
  final String destinationAddress;
  final String expiresAt;
  final int maximumHopCount;

  const SupervisedValidationAuthorization({
    required this.engagementReference,
    required this.observingOperator,
    required this.sourceAddress,
    required this.destinationAddress,
    required this.expiresAt,
    this.maximumHopCount = 1,
  });

  DateTime? get expiry => DateTime.tryParse(expiresAt)?.toUtc();
}

class SupervisedValidationAction {
  final String actionId;
  final String exactAction;
  final String sourceAddress;
  final String destinationAddress;
  final int hopCount;
  final bool opensRemoteSession;
  final bool changesState;
  final bool reversible;
  final bool destructive;
  final bool readsSecrets;
  final bool bypassesMfa;
  final bool createsPersistence;
  final bool startsListener;
  final bool escalatesPrivileges;
  final List<String> cleanupActions;
  final String cleanupVerification;

  const SupervisedValidationAction({
    required this.actionId,
    this.exactAction = '',
    required this.sourceAddress,
    required this.destinationAddress,
    required this.hopCount,
    this.opensRemoteSession = false,
    this.changesState = false,
    this.reversible = false,
    this.destructive = false,
    this.readsSecrets = false,
    this.bypassesMfa = false,
    this.createsPersistence = false,
    this.startsListener = false,
    this.escalatesPrivileges = false,
    this.cleanupActions = const [],
    this.cleanupVerification = '',
  });
}

class SupervisedValidationDecision {
  final bool allowed;
  final bool cleanupRequired;
  final bool requiresPerActionApproval;
  final bool aiOperated;
  final String reason;

  const SupervisedValidationDecision({
    required this.allowed,
    required this.cleanupRequired,
    this.requiresPerActionApproval = true,
    this.aiOperated = true,
    required this.reason,
  });
}

/// Fail-closed policy for human-supervised, AI-operated validation.
///
/// This gate is intentionally separate from ordinary Recon/Proof consent and
/// never consumes persistent command or tool approvals.
class SupervisedValidationPolicy {
  const SupervisedValidationPolicy();

  SupervisedValidationDecision evaluate({
    required SupervisedValidationAuthorization authorization,
    required SupervisedValidationAction action,
    required DateTime now,
    required bool observerPresent,
    required bool exactActionApproved,
    bool persistentConsentPresent = false,
  }) {
    if (authorization.engagementReference.trim().isEmpty ||
        authorization.observingOperator.trim().isEmpty) {
      return _block(
        'Engagement authorization and observing operator are required.',
      );
    }
    if (InternetAddress.tryParse(authorization.sourceAddress) == null ||
        InternetAddress.tryParse(authorization.destinationAddress) == null) {
      return _block(
        'The exact authorized source and destination address must be valid IP addresses.',
      );
    }
    final expiry = authorization.expiry;
    if (expiry == null || !now.toUtc().isBefore(expiry)) {
      return _block(
        'The supervised authorization is missing, invalid, or expired.',
      );
    }
    if (!observerPresent) {
      return _block('A human observer must remain present for every action.');
    }
    if (!exactActionApproved) {
      return _block(
        'The exact action requires fresh operator approval; persistent consent is not accepted.',
      );
    }
    if (action.sourceAddress != authorization.sourceAddress ||
        action.destinationAddress != authorization.destinationAddress) {
      return _block(
        'The action is outside the exact authorized source/destination pair.',
      );
    }
    if (action.hopCount < 0 ||
        action.hopCount > authorization.maximumHopCount ||
        authorization.maximumHopCount > 1) {
      return _block(
        'Movement is limited to the single specifically authorized hop.',
      );
    }
    if (action.destructive) {
      return _block('Destructive actions are prohibited.');
    }
    if (action.readsSecrets) {
      return _block('Credential and secret extraction are prohibited.');
    }
    if (action.bypassesMfa) {
      return _block('MFA bypass or weakening is prohibited.');
    }
    if (action.createsPersistence) {
      return _block('Persistence and backdoors are prohibited.');
    }
    if (action.startsListener) {
      return _block('External callbacks and listeners are prohibited.');
    }
    if (action.escalatesPrivileges) {
      return _block(
        'Privilege escalation requires a separate supervised procedure.',
      );
    }
    if (action.changesState &&
        (!action.reversible ||
            action.cleanupActions.isEmpty ||
            action.cleanupVerification.trim().isEmpty)) {
      return _block(
        'A state-changing action must be reversible with predefined cleanup and verification.',
      );
    }
    return SupervisedValidationDecision(
      allowed: true,
      cleanupRequired: action.changesState,
      reason: action.changesState
          ? 'Approved bounded action may run; cleanup verification is mandatory.'
          : 'Approved bounded read-only action may run under continuous observation.',
    );
  }

  SupervisedValidationDecision _block(String reason) =>
      SupervisedValidationDecision(
        allowed: false,
        cleanupRequired: false,
        reason: reason,
      );
}
