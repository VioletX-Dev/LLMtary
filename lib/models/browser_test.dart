enum BrowserActionKind {
  navigate,
  click,
  fill,
  submit,
  switchRole,
  captureState,
}

class BrowserActionRequest {
  final BrowserActionKind kind;
  final String url;
  final String selector;
  final String value;
  final String roleId;

  const BrowserActionRequest({
    required this.kind,
    this.url = '',
    this.selector = '',
    this.value = '',
    this.roleId = '',
  });
}

class BrowserNetworkExchange {
  final String method;
  final String url;
  final int statusCode;
  final Map<String, String> requestHeaders;
  final Map<String, String> responseHeaders;

  const BrowserNetworkExchange({
    required this.method,
    required this.url,
    required this.statusCode,
    this.requestHeaders = const {},
    this.responseHeaders = const {},
  });
}

class BrowserDriverObservation {
  final String url;
  final int statusCode;
  final String domSnapshot;
  final List<BrowserNetworkExchange> networkExchanges;
  final int? screenshotEvidenceArtifactId;

  const BrowserDriverObservation({
    required this.url,
    required this.statusCode,
    required this.domSnapshot,
    this.networkExchanges = const [],
    this.screenshotEvidenceArtifactId,
  });
}

abstract interface class BrowserDriver {
  Future<BrowserDriverObservation> perform(BrowserActionRequest request);
}

class BrowserActionRecord {
  final BrowserActionKind kind;
  final String action;
  final String roleId;
  final String finalUrl;
  final int statusCode;
  final String domSha256;
  final List<BrowserNetworkExchange> networkExchanges;
  final List<int> evidenceArtifactIds;

  const BrowserActionRecord({
    required this.kind,
    required this.action,
    required this.roleId,
    required this.finalUrl,
    required this.statusCode,
    required this.domSha256,
    this.networkExchanges = const [],
    this.evidenceArtifactIds = const [],
  });
}
