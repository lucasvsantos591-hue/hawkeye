import ast
from typing import Dict, Set, Optional, List
from dataclasses import dataclass


@dataclass
class CallGraphNode:
    id: str
    type: str  # 'function', 'method', 'class', etc
    file_name: Optional[str] = None
    line_number: Optional[int] = None
    called_functions: Set[str] = None
    called_by_functions: Set[str] = None
    is_entry_point: bool = False

    def __post_init__(self):
        if self.called_functions is None:
            self.called_functions = set()
        if self.called_by_functions is None:
            self.called_by_functions = set()


class PythonCallGraphBuilder(ast.NodeVisitor):
    """Build call graph from Python source code."""

    def __init__(self, filename: str = "unknown.py"):
        self.call_graph: Dict[str, CallGraphNode] = {}
        self.current_function: Optional[str] = None
        self.current_class: Optional[str] = None
        self.filename = filename

    def build_from_source(self, source_code: str) -> Dict[str, CallGraphNode]:
        """Parse source code and build call graph."""
        try:
            tree = ast.parse(source_code)
            self.visit(tree)
        except SyntaxError as e:
            print(f"Failed to parse {self.filename}: {e}")

        return self.call_graph

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Visit function definition."""
        func_name = node.name

        # Qualify with class name if inside a class
        if self.current_class:
            full_name = f"{self.current_class}.{func_name}"
            node_type = "method"
        else:
            full_name = func_name
            node_type = "function"

        # Create or get node
        self.get_or_create_node(full_name, node_type, node.lineno)

        # Visit function body
        prev_func = self.current_function
        self.current_function = full_name

        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                self.record_call(child)

        # Visit children to handle nested functions
        for child in node.body:
            self.visit(child)

        self.current_function = prev_func

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        """Visit async function definition."""
        # Treat similar to regular functions
        func_name = node.name

        if self.current_class:
            full_name = f"{self.current_class}.{func_name}"
            node_type = "method"
        else:
            full_name = func_name
            node_type = "function"

        self.get_or_create_node(full_name, node_type, node.lineno)

        prev_func = self.current_function
        self.current_function = full_name

        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                self.record_call(child)

        for child in node.body:
            self.visit(child)

        self.current_function = prev_func

    def visit_ClassDef(self, node: ast.ClassDef):
        """Visit class definition."""
        self.get_or_create_node(node.name, "class", node.lineno)

        prev_class = self.current_class
        self.current_class = node.name

        self.generic_visit(node)

        self.current_class = prev_class

    def record_call(self, node: ast.Call):
        """Record a function call in the current function."""
        if not self.current_function:
            return

        callee_name = self.extract_call_target(node.func)
        if callee_name:
            caller = self.call_graph.get(self.current_function)
            if caller:
                caller.called_functions.add(callee_name)
                callee = self.get_or_create_node(callee_name, "function")
                callee.called_by_functions.add(self.current_function)

    def extract_call_target(self, node: ast.expr) -> Optional[str]:
        """Extract function/method name from a call node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            # obj.method() -> "obj.method"
            value_name = self.extract_call_target(node.value)
            if value_name:
                return f"{value_name}.{node.attr}"
            return f"<unknown>.{node.attr}"
        elif isinstance(node, ast.Call):
            # Recursive call
            return self.extract_call_target(node.func)

        return None

    def get_or_create_node(
        self,
        node_id: str,
        node_type: str = "function",
        line_number: Optional[int] = None,
    ) -> CallGraphNode:
        """Get or create a call graph node."""
        if node_id not in self.call_graph:
            self.call_graph[node_id] = CallGraphNode(
                id=node_id,
                type=node_type,
                file_name=self.filename,
                line_number=line_number,
            )
        return self.call_graph[node_id]

    def to_dict(self) -> Dict[str, Dict]:
        """Convert call graph to dictionary."""
        result = {}
        for node_id, node in self.call_graph.items():
            result[node_id] = {
                "id": node.id,
                "type": node.type,
                "file_name": node.file_name,
                "line_number": node.line_number,
                "called_functions": list(node.called_functions),
                "called_by_functions": list(node.called_by_functions),
                "is_entry_point": node.is_entry_point,
            }
        return result


# Convenience function
def build_call_graph(source_code: str, filename: str = "unknown.py") -> Dict[str, CallGraphNode]:
    """Build call graph from Python source code."""
    builder = PythonCallGraphBuilder(filename)
    return builder.build_from_source(source_code)
