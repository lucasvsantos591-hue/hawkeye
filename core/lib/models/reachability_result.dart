import 'vulnerability.dart';

/// Represents data flow from source to sink
class DataFlowPath {
  final String source; // e.g., "user_input", "network"
  final List<String> path; // Function call chain
  final String sink; // Vulnerable function
  final String dataType; // Type of tainted data
  final double confidence; // 0-1

  DataFlowPath({
    required this.source,
    required this.path,
    required this.sink,
    required this.dataType,
    this.confidence = 0.8,
  });

  factory DataFlowPath.fromJson(Map<String, dynamic> json) {
    return DataFlowPath(
      source: json['source'] as String,
      path: List<String>.from(json['path'] as List),
      sink: json['sink'] as String,
      dataType: json['data_type'] as String,
      confidence: (json['confidence'] as num?)?.toDouble() ?? 0.8,
    );
  }

  Map<String, dynamic> toJson() => {
    'source': source,
    'path': path,
    'sink': sink,
    'data_type': dataType,
    'confidence': confidence,
  };
}

/// Affected file location
class AffectedFile {
  final String filePath;
  final int? lineNumber;
  final int? columnNumber;
  final String? snippet; // Code snippet

  AffectedFile({
    required this.filePath,
    this.lineNumber,
    this.columnNumber,
    this.snippet,
  });

  factory AffectedFile.fromJson(Map<String, dynamic> json) {
    return AffectedFile(
      filePath: json['file_path'] as String,
      lineNumber: json['line_number'] as int?,
      columnNumber: json['column_number'] as int?,
      snippet: json['snippet'] as String?,
    );
  }

  Map<String, dynamic> toJson() => {
    'file_path': filePath,
    'line_number': lineNumber,
    'column_number': columnNumber,
    'snippet': snippet,
  };
}

/// Result of reachability analysis for a single vulnerability
class VulnerabilityReachabilityResult {
  final Vulnerability vulnerability;

  /// Reachability level (1=import, 2=call chain, 3=data flow)
  final int reachabilityLevel;

  /// Is the vulnerability actually reachable in this project?
  final bool isReachable;

  /// Confidence score (0-100)
  final int confidence;

  /// Call chain from entry point to vulnerable function
  final List<String>? callChain;

  /// Data flows that could trigger the vulnerability
  final List<DataFlowPath>? taintedDataFlows;

  /// Affected files in the project
  final List<AffectedFile> affectedFiles;

  /// Remediation advice
  final String? remediationAdvice;

  /// Additional metadata
  final Map<String, dynamic>? metadata;

  VulnerabilityReachabilityResult({
    required this.vulnerability,
    required this.reachabilityLevel,
    required this.isReachable,
    this.confidence = 0,
    this.callChain,
    this.taintedDataFlows,
    this.affectedFiles = const [],
    this.remediationAdvice,
    this.metadata,
  });

  /// Get risk score based on severity and reachability
  int getRiskScore() {
    const severityScores = {
      'CRITICAL': 100,
      'HIGH': 80,
      'MEDIUM': 50,
      'LOW': 20,
    };

    final baseScore = severityScores[vulnerability.severity] ?? 0;
    if (!isReachable) return baseScore ~/ 10; // Divide by 10 if unreachable

    // Boost score based on reachability level
    final reachabilityBoost = reachabilityLevel * 10;
    return ((baseScore + reachabilityBoost) * (confidence / 100)).toInt();
  }

  String get reachabilityDescription {
    switch (reachabilityLevel) {
      case 1:
        return 'Library imported but function not called';
      case 2:
        return 'Function reachable from entry point';
      case 3:
        return 'Tainted data can flow to vulnerability';
      default:
        return 'Not analyzed';
    }
  }

  factory VulnerabilityReachabilityResult.fromJson(Map<String, dynamic> json) {
    return VulnerabilityReachabilityResult(
      vulnerability: Vulnerability.fromJson(json['vulnerability'] as Map<String, dynamic>),
      reachabilityLevel: json['reachability_level'] as int,
      isReachable: json['is_reachable'] as bool,
      confidence: json['confidence'] as int? ?? 0,
      callChain: (json['call_chain'] as List?)?.cast<String>(),
      taintedDataFlows: (json['tainted_data_flows'] as List?)
          ?.map((f) => DataFlowPath.fromJson(f as Map<String, dynamic>))
          .toList(),
      affectedFiles: (json['affected_files'] as List?)
          ?.map((f) => AffectedFile.fromJson(f as Map<String, dynamic>))
          .toList() ?? [],
      remediationAdvice: json['remediation_advice'] as String?,
      metadata: json['metadata'] as Map<String, dynamic>?,
    );
  }

  Map<String, dynamic> toJson() => {
    'vulnerability': vulnerability.toJson(),
    'reachability_level': reachabilityLevel,
    'is_reachable': isReachable,
    'confidence': confidence,
    'call_chain': callChain,
    'tainted_data_flows': taintedDataFlows?.map((f) => f.toJson()).toList(),
    'affected_files': affectedFiles.map((f) => f.toJson()).toList(),
    'remediation_advice': remediationAdvice,
    'metadata': metadata,
  };

  @override
  String toString() =>
    '${vulnerability.cveId} in ${vulnerability.package}: '
    'Level $reachabilityLevel, Reachable: $isReachable, Risk: ${getRiskScore()}';
}

/// Complete analysis report for a project
class AnalysisReport {
  final String projectName;
  final String projectPath;
  final String language;
  final DateTime analysisTimestamp;
  final Duration analysisTime;

  /// All results (reachable + unreachable)
  final List<VulnerabilityReachabilityResult> results;

  /// Metadata about the analysis
  final Map<String, dynamic>? metadata;

  AnalysisReport({
    required this.projectName,
    required this.projectPath,
    required this.language,
    required this.results,
    this.analysisTimestamp = const Duration() == const Duration()
        ? null
        : DateTime.now(),
    this.analysisTime = const Duration(),
    this.metadata,
  })  : analysisTimestamp = analysisTimestamp ?? DateTime.now(),
        analysisTime = analysisTime == const Duration() ? Duration.zero : analysisTime;

  /// Get only reachable vulnerabilities
  List<VulnerabilityReachabilityResult> getReachableVulnerabilities() {
    return results.where((r) => r.isReachable).toList();
  }

  /// Get vulnerabilities by severity
  List<VulnerabilityReachabilityResult> getByS everity(String severity) {
    return results.where((r) => r.vulnerability.severity == severity).toList();
  }

  /// Calculate overall risk score (0-100)
  int getOverallRiskScore() {
    if (results.isEmpty) return 0;
    final scores = results.map((r) => r.getRiskScore()).toList();
    return (scores.reduce((a, b) => a + b) / results.length).round();
  }

  /// Summary statistics
  Map<String, int> getSummary() {
    return {
      'total_vulnerabilities': results.length,
      'reachable_vulnerabilities': getReachableVulnerabilities().length,
      'critical_reachable': getByS everity('CRITICAL').where((r) => r.isReachable).length,
      'high_reachable': getByS everity('HIGH').where((r) => r.isReachable).length,
      'medium_reachable': getByS everity('MEDIUM').where((r) => r.isReachable).length,
      'low_reachable': getByS everity('LOW').where((r) => r.isReachable).length,
      'overall_risk_score': getOverallRiskScore(),
    };
  }

  factory AnalysisReport.fromJson(Map<String, dynamic> json) {
    return AnalysisReport(
      projectName: json['project_name'] as String,
      projectPath: json['project_path'] as String,
      language: json['language'] as String,
      analysisTimestamp: DateTime.parse(json['analysis_timestamp'] as String),
      analysisTime: Duration(
        milliseconds: json['analysis_time_ms'] as int? ?? 0,
      ),
      results: (json['results'] as List)
          .map((r) => VulnerabilityReachabilityResult.fromJson(r as Map<String, dynamic>))
          .toList(),
      metadata: json['metadata'] as Map<String, dynamic>?,
    );
  }

  Map<String, dynamic> toJson() => {
    'project_name': projectName,
    'project_path': projectPath,
    'language': language,
    'analysis_timestamp': analysisTimestamp.toIso8601String(),
    'analysis_time_ms': analysisTime.inMilliseconds,
    'results': results.map((r) => r.toJson()).toList(),
    'metadata': metadata,
    ...getSummary(),
  };

  @override
  String toString() {
    final summary = getSummary();
    return '$projectName: ${summary['total_vulnerabilities']} vulns, '
        '${summary['reachable_vulnerabilities']} reachable, '
        'Risk: ${summary['overall_risk_score']}/100';
  }
}
