/// Represents a single dependency (direct or transitive)
class Dependency {
  final String name;
  final String version;
  final String language; // 'javascript', 'python', etc
  final List<Dependency> dependencies; // Transitive dependencies
  final bool isDirect;
  final String? source; // 'npm', 'pypi', 'maven', etc
  final String? repositoryUrl;

  Dependency({
    required this.name,
    required this.version,
    required this.language,
    this.dependencies = const [],
    this.isDirect = false,
    this.source,
    this.repositoryUrl,
  });

  factory Dependency.fromJson(Map<String, dynamic> json) {
    return Dependency(
      name: json['name'] as String,
      version: json['version'] as String,
      language: json['language'] as String,
      dependencies: (json['dependencies'] as List?)
          ?.map((d) => Dependency.fromJson(d as Map<String, dynamic>))
          .toList() ?? [],
      isDirect: json['is_direct'] as bool? ?? false,
      source: json['source'] as String?,
      repositoryUrl: json['repository_url'] as String?,
    );
  }

  Map<String, dynamic> toJson() => {
    'name': name,
    'version': version,
    'language': language,
    'dependencies': dependencies.map((d) => d.toJson()).toList(),
    'is_direct': isDirect,
    'source': source,
    'repository_url': repositoryUrl,
  };

  /// Get all transitive dependencies flattened
  List<Dependency> getAllTransitiveDependencies() {
    final result = <Dependency>[];
    final visited = <String>{};

    void traverse(Dependency dep) {
      if (visited.contains(dep.name)) return;
      visited.add(dep.name);
      result.add(dep);
      for (final transitive in dep.dependencies) {
        traverse(transitive);
      }
    }

    for (final dep in dependencies) {
      traverse(dep);
    }

    return result;
  }

  /// Returns a unique identifier for this dependency
  String get identifier => '$name@$version';

  @override
  String toString() => '$name@$version';

  @override
  bool operator ==(Object other) =>
    identical(this, other) ||
    other is Dependency &&
    runtimeType == other.runtimeType &&
    name == other.name &&
    version == other.version &&
    language == other.language;

  @override
  int get hashCode => Object.hash(name, version, language);
}

/// Represents the complete dependency tree
class DependencyTree {
  final String projectName;
  final String language;
  final List<Dependency> directDependencies;
  final DateTime resolvedAt;
  final String? manifestPath; // Path to package.json, requirements.txt, etc

  DependencyTree({
    required this.projectName,
    required this.language,
    required this.directDependencies,
    this.resolvedAt = const Duration() == const Duration()
        ? null
        : DateTime.now(),
    this.manifestPath,
  }) : resolvedAt = resolvedAt ?? DateTime.now();

  /// Get all dependencies (direct + transitive)
  List<Dependency> getAllDependencies() {
    final result = <Dependency>[];
    final visited = <String>{};

    void traverse(Dependency dep) {
      if (visited.contains(dep.name)) return;
      visited.add(dep.name);
      result.add(dep);
      for (final transitive in dep.dependencies) {
        traverse(transitive);
      }
    }

    for (final dep in directDependencies) {
      traverse(dep);
    }

    return result;
  }

  /// Get dependency by name and optionally version
  Dependency? findDependency(String name, {String? version}) {
    for (final dep in getAllDependencies()) {
      if (dep.name == name) {
        if (version == null || dep.version == version) {
          return dep;
        }
      }
    }
    return null;
  }

  factory DependencyTree.fromJson(Map<String, dynamic> json) {
    return DependencyTree(
      projectName: json['project_name'] as String,
      language: json['language'] as String,
      directDependencies: (json['direct_dependencies'] as List)
          .map((d) => Dependency.fromJson(d as Map<String, dynamic>))
          .toList(),
      resolvedAt: json['resolved_at'] != null
          ? DateTime.parse(json['resolved_at'] as String)
          : DateTime.now(),
      manifestPath: json['manifest_path'] as String?,
    );
  }

  Map<String, dynamic> toJson() => {
    'project_name': projectName,
    'language': language,
    'direct_dependencies': directDependencies.map((d) => d.toJson()).toList(),
    'resolved_at': resolvedAt.toIso8601String(),
    'manifest_path': manifestPath,
  };

  @override
  String toString() => '$projectName ($language): ${directDependencies.length} direct dependencies';
}
