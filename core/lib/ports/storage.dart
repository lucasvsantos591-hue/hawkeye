import '../models/vulnerability.dart';

/// Port interface for storage/caching layer
/// Implementations can use SQLite, Redis, in-memory, etc.
abstract class VulnerabilityStorage {
  /// Save vulnerability to cache
  Future<void> saveVulnerability(Vulnerability vuln);

  /// Get vulnerability from cache
  Future<Vulnerability?> getVulnerability(String cveId);

  /// Get all cached vulnerabilities for a package
  Future<List<Vulnerability>> getByPackage(
    String package, {
    String? version,
    String? language,
  });

  /// Check if vulnerability is in cache
  Future<bool> hasVulnerability(String cveId);

  /// Clear cache for a package
  Future<void> clearPackageCache(String package);

  /// Clear all cache
  Future<void> clearAllCache();

  /// Get cache statistics
  Future<CacheStats> getStats();

  /// Close storage connection
  Future<void> close();
}

/// Statistics about the cache
class CacheStats {
  final int totalVulnerabilities;
  final int totalPackages;
  final DateTime? lastUpdated;
  final int cacheSize; // in bytes

  CacheStats({
    required this.totalVulnerabilities,
    required this.totalPackages,
    this.lastUpdated,
    required this.cacheSize,
  });

  factory CacheStats.fromJson(Map<String, dynamic> json) {
    return CacheStats(
      totalVulnerabilities: json['total_vulnerabilities'] as int,
      totalPackages: json['total_packages'] as int,
      lastUpdated: json['last_updated'] != null
          ? DateTime.parse(json['last_updated'] as String)
          : null,
      cacheSize: json['cache_size'] as int,
    );
  }

  Map<String, dynamic> toJson() => {
    'total_vulnerabilities': totalVulnerabilities,
    'total_packages': totalPackages,
    'last_updated': lastUpdated?.toIso8601String(),
    'cache_size': cacheSize,
  };

  @override
  String toString() =>
    'Cache: $totalVulnerabilities vulnerabilities, $totalPackages packages, '
    'Size: ${(cacheSize / 1024 / 1024).toStringAsFixed(2)} MB';
}
