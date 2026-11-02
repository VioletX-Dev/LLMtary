enum ContextArtifactType {
  apiSpecification,
  soapSpecification,
  sourceArchive,
  architectureDocument,
  priorReport,
  dependencyManifest,
  unknown,
}

class ContextArtifact {
  final int? id;
  final int projectId;
  final ContextArtifactType type;
  final String originalFileName;
  final String sha256;
  final int sizeBytes;
  final String extractionMethod;
  final DateTime ingestedAt;

  const ContextArtifact({
    this.id,
    required this.projectId,
    required this.type,
    required this.originalFileName,
    required this.sha256,
    required this.sizeBytes,
    required this.extractionMethod,
    required this.ingestedAt,
  });
}

class ContextProvenance {
  final String sourceDigest;
  final String parserVersion;
  final String sourceName;
  final DateTime extractedAt;

  const ContextProvenance({
    required this.sourceDigest,
    required this.parserVersion,
    required this.sourceName,
    required this.extractedAt,
  });
}

class ApiEndpointContext {
  final String method;
  final String path;
  final String operationId;
  final List<String> parameterNames;
  final List<String> securitySchemes;

  const ApiEndpointContext({
    required this.method,
    required this.path,
    this.operationId = '',
    this.parameterNames = const [],
    this.securitySchemes = const [],
  });
}

class DependencyContext {
  final String name;
  final String versionConstraint;
  final String ecosystem;
  final bool developmentOnly;

  const DependencyContext({
    required this.name,
    required this.versionConstraint,
    required this.ecosystem,
    this.developmentOnly = false,
  });
}

class PriorFindingContext {
  final String title;
  final String severity;
  final String status;
  final String evidence;
  final String remediation;

  const PriorFindingContext({
    required this.title,
    this.severity = '',
    this.status = '',
    this.evidence = '',
    this.remediation = '',
  });
}

class ContextArchiveEntry {
  final String path;
  final String sha256;
  final int sizeBytes;

  const ContextArchiveEntry({
    required this.path,
    required this.sha256,
    required this.sizeBytes,
  });
}

class ContextIngestionResult {
  final ContextArtifact artifact;
  final ContextProvenance provenance;
  final List<ApiEndpointContext> apiEndpoints;
  final List<DependencyContext> dependencies;
  final List<PriorFindingContext> priorFindings;
  final List<ContextArchiveEntry> archiveEntries;
  final String normalizedText;

  const ContextIngestionResult({
    required this.artifact,
    required this.provenance,
    this.apiEndpoints = const [],
    this.dependencies = const [],
    this.priorFindings = const [],
    this.archiveEntries = const [],
    this.normalizedText = '',
  });
}
