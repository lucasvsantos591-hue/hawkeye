import '../models/dependency.dart';

/// Port interface for dependency resolvers
/// Implementations can handle package.json, requirements.txt, pom.xml, etc.
abstract class DependencyResolver {
  /// Supported language/ecosystem
  String get language;

  /// Resolve dependencies from project directory
  Future<DependencyTree> resolveDependencies(String projectPath);

  /// Check if this resolver can handle the given project
  bool canHandle(String projectPath);

  /// Get manifest file name(s) that this resolver looks for
  List<String> get manifestFileNames;
}
