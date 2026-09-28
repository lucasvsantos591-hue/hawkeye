import '../models/call_graph.dart';

/// Port interface for AST parsing and call graph building
/// Implementations for TypeScript, Python, etc.
abstract class AstParser {
  /// Supported language
  String get language;

  /// Parse source code and build call graph
  Future<CallGraph> parseAndBuildCallGraph(
    String sourceCode, {
    required String filePath,
    Map<String, dynamic>? options,
  });

  /// Parse source code to extract imports
  Future<List<String>> extractImports(String sourceCode);

  /// Parse source code to extract function/method definitions
  Future<Map<String, FunctionDefinition>> extractFunctionDefinitions(String sourceCode);

  /// Check if this parser supports the given file extension
  bool supports(String fileExtension);
}

/// Represents a function/method definition
class FunctionDefinition {
  final String name;
  final String type; // 'function', 'method', 'class', etc
  final String? className;
  final List<String> parameters;
  final List<String> calledFunctions; // Functions this one calls
  final int startLine;
  final int endLine;
  final bool isExported;
  final Map<String, dynamic>? metadata;

  FunctionDefinition({
    required this.name,
    required this.type,
    this.className,
    this.parameters = const [],
    this.calledFunctions = const [],
    required this.startLine,
    required this.endLine,
    this.isExported = false,
    this.metadata,
  });

  factory FunctionDefinition.fromJson(Map<String, dynamic> json) {
    return FunctionDefinition(
      name: json['name'] as String,
      type: json['type'] as String,
      className: json['class_name'] as String?,
      parameters: List<String>.from(json['parameters'] as List? ?? []),
      calledFunctions: List<String>.from(json['called_functions'] as List? ?? []),
      startLine: json['start_line'] as int,
      endLine: json['end_line'] as int,
      isExported: json['is_exported'] as bool? ?? false,
      metadata: json['metadata'] as Map<String, dynamic>?,
    );
  }

  Map<String, dynamic> toJson() => {
    'name': name,
    'type': type,
    'class_name': className,
    'parameters': parameters,
    'called_functions': calledFunctions,
    'start_line': startLine,
    'end_line': endLine,
    'is_exported': isExported,
    'metadata': metadata,
  };

  String get fullName => className != null ? '$className.$name' : name;

  @override
  String toString() => '$type $fullName (line $startLine-$endLine)';
}
