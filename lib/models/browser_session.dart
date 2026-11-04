enum BrowserSessionStatus { active, closing, closed, failed }

class BrowserFormFieldState {
  final String selector;
  final String name;
  final String type;
  final bool required;
  final bool disabled;

  const BrowserFormFieldState({
    required this.selector,
    required this.name,
    required this.type,
    this.required = false,
    this.disabled = false,
  });

  Map<String, Object?> toMap() => {
        'selector': selector,
        'name': name,
        'type': type,
        'required': required,
        'disabled': disabled,
      };

  factory BrowserFormFieldState.fromMap(Map<String, Object?> map) =>
      BrowserFormFieldState(
        selector: map['selector'] as String? ?? '',
        name: map['name'] as String? ?? '',
        type: map['type'] as String? ?? 'text',
        required: map['required'] == true,
        disabled: map['disabled'] == true,
      );
}

class BrowserFormState {
  final String selector;
  final String method;
  final String action;
  final List<BrowserFormFieldState> fields;

  const BrowserFormState({
    required this.selector,
    required this.method,
    required this.action,
    this.fields = const [],
  });

  Map<String, Object?> toMap() => {
        'selector': selector,
        'method': method,
        'action': action,
        'fields': fields.map((field) => field.toMap()).toList(growable: false),
      };

  factory BrowserFormState.fromMap(Map<String, Object?> map) => BrowserFormState(
        selector: map['selector'] as String? ?? '',
        method: map['method'] as String? ?? 'GET',
        action: map['action'] as String? ?? '',
        fields: ((map['fields'] as List?) ?? const [])
            .map((item) => BrowserFormFieldState.fromMap(
                  Map<String, Object?>.from(item as Map),
                ))
            .toList(growable: false),
      );
}

class BrowserSessionNetworkExchange {
  final String method;
  final String url;
  final int statusCode;

  const BrowserSessionNetworkExchange({
    required this.method,
    required this.url,
    required this.statusCode,
  });

  Map<String, Object?> toMap() => {
        'method': method,
        'url': url,
        'statusCode': statusCode,
      };

  factory BrowserSessionNetworkExchange.fromMap(Map<String, Object?> map) =>
      BrowserSessionNetworkExchange(
        method: map['method'] as String? ?? '',
        url: map['url'] as String? ?? '',
        statusCode: map['statusCode'] as int? ?? 0,
      );
}

class BrowserSessionSnapshot {
  final String sessionId;
  final int projectId;
  final String roleId;
  final BrowserSessionStatus status;
  final DateTime createdAt;
  final DateTime lastActiveAt;
  final String currentUrl;
  final String domSha256;
  final List<BrowserFormState> forms;
  final List<BrowserSessionNetworkExchange> networkExchanges;
  final List<int> evidenceArtifactIds;

  const BrowserSessionSnapshot({
    required this.sessionId,
    required this.projectId,
    required this.roleId,
    required this.status,
    required this.createdAt,
    required this.lastActiveAt,
    required this.currentUrl,
    required this.domSha256,
    this.forms = const [],
    this.networkExchanges = const [],
    this.evidenceArtifactIds = const [],
  });

  BrowserSessionSnapshot copyWith({
    BrowserSessionStatus? status,
    DateTime? lastActiveAt,
  }) =>
      BrowserSessionSnapshot(
        sessionId: sessionId,
        projectId: projectId,
        roleId: roleId,
        status: status ?? this.status,
        createdAt: createdAt,
        lastActiveAt: lastActiveAt ?? this.lastActiveAt,
        currentUrl: currentUrl,
        domSha256: domSha256,
        forms: forms,
        networkExchanges: networkExchanges,
        evidenceArtifactIds: evidenceArtifactIds,
      );
}
