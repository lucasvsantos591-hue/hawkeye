/// Represents a node in the call graph
class CallGraphNode {
  final String id; // function name or "module.function"
  final String type; // 'function', 'method', 'class', 'module'
  final String? fileName;
  final int? lineNumber;
  final Set<String> calledFunctions; // Functions this node calls
  final Set<String> calledByFunctions; // Functions that call this node
  final bool isEntryPoint; // main(), export, etc
  final Map<String, dynamic>? metadata;

  CallGraphNode({
    required this.id,
    required this.type,
    this.fileName,
    this.lineNumber,
    this.calledFunctions = const {},
    this.calledByFunctions = const {},
    this.isEntryPoint = false,
    this.metadata,
  });

  /// Check if this node calls another function (directly or transitively)
  bool callsFunction(String functionId, {int maxDepth = 100}) {
    if (maxDepth <= 0) return false;
    if (calledFunctions.contains(functionId)) return true;
    return false; // Transitive check would need full graph
  }

  factory CallGraphNode.fromJson(Map<String, dynamic> json) {
    return CallGraphNode(
      id: json['id'] as String,
      type: json['type'] as String,
      fileName: json['file_name'] as String?,
      lineNumber: json['line_number'] as int?,
      calledFunctions: Set<String>.from(json['called_functions'] as List? ?? []),
      calledByFunctions: Set<String>.from(json['called_by_functions'] as List? ?? []),
      isEntryPoint: json['is_entry_point'] as bool? ?? false,
      metadata: json['metadata'] as Map<String, dynamic>?,
    );
  }

  Map<String, dynamic> toJson() => {
    'id': id,
    'type': type,
    'file_name': fileName,
    'line_number': lineNumber,
    'called_functions': calledFunctions.toList(),
    'called_by_functions': calledByFunctions.toList(),
    'is_entry_point': isEntryPoint,
    'metadata': metadata,
  };
}

/// Represents the complete call graph for a project
class CallGraph {
  final String language; // 'javascript', 'python', etc
  final Map<String, CallGraphNode> nodes;
  final DateTime builtAt;

  CallGraph({
    required this.language,
    this.nodes = const {},
    DateTime? builtAt,
  }) : builtAt = builtAt ?? DateTime.now();

  /// Get all entry points (main, exports, etc)
  List<CallGraphNode> getEntryPoints() {
    return nodes.values.where((node) => node.isEntryPoint).toList();
  }

  /// Find all functions reachable from an entry point
  Set<String> getReachableFunctions(String entryPointId, {int maxDepth = 1000}) {
    final reachable = <String>{};
    final queue = <String>[entryPointId];
    final visited = <String>{};

    while (queue.isNotEmpty && visited.length < maxDepth) {
      final current = queue.removeAt(0);
      if (visited.contains(current)) continue;
      visited.add(current);
      reachable.add(current);

      final node = nodes[current];
      if (node != null) {
        for (final called in node.calledFunctions) {
          if (!visited.contains(called)) {
            queue.add(called);
          }
        }
      }
    }

    return reachable;
  }

  /// Check if a function is reachable from any entry point
  bool isFunctionReachable(String functionId) {
    for (final entryPoint in getEntryPoints()) {
      if (getReachableFunctions(entryPoint.id).contains(functionId)) {
        return true;
      }
    }
    return false;
  }

  /// Find the shortest call chain from entry point to target function
  List<String>? findCallChain(String entryPointId, String targetFunctionId) {
    final queue = <(String, List<String>)>[(entryPointId, [entryPointId])];
    final visited = <String>{};

    while (queue.isNotEmpty) {
      final (current, path) = queue.removeAt(0);

      if (current == targetFunctionId) {
        return path;
      }

      if (visited.contains(current)) continue;
      visited.add(current);

      final node = nodes[current];
      if (node != null) {
        for (final called in node.calledFunctions) {
          if (!visited.contains(called)) {
            queue.add((called, [...path, called]));
          }
        }
      }
    }

    return null;
  }

  /// Add a node to the graph
  void addNode(CallGraphNode node) {
    nodes[node.id] = node;
  }

  /// Add a call edge (a calls b)
  void addCall(String callerId, String calleeId) {
    final caller = nodes[callerId];
    final callee = nodes[calleeId];

    if (caller != null) {
      (caller.calledFunctions as Set<String>).add(calleeId);
    }
    if (callee != null) {
      (callee.calledByFunctions as Set<String>).add(callerId);
    }
  }

  factory CallGraph.fromJson(Map<String, dynamic> json) {
    final nodesData = json['nodes'] as Map<String, dynamic>? ?? {};
    final nodes = <String, CallGraphNode>{};

    nodesData.forEach((id, data) {
      nodes[id] = CallGraphNode.fromJson({'id': id, ...data as Map<String, dynamic>});
    });

    return CallGraph(
      language: json['language'] as String,
      nodes: nodes,
      builtAt: json['built_at'] != null
          ? DateTime.parse(json['built_at'] as String)
          : DateTime.now(),
    );
  }

  Map<String, dynamic> toJson() => {
    'language': language,
    'nodes': {
      for (final node in nodes.values)
        node.id: node.toJson()
    },
    'built_at': builtAt.toIso8601String(),
  };

  @override
  String toString() => 'CallGraph($language): ${nodes.length} nodes, ${getEntryPoints().length} entry points';
}
