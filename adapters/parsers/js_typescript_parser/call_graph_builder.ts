import * as t from '@babel/types';
import traverse from '@babel/traverse';
import { parse } from '@babel/parser';

export interface CallGraphNode {
  id: string;
  type: 'function' | 'method' | 'class' | 'module';
  fileName?: string;
  lineNumber?: number;
  calledFunctions: Set<string>;
  calledByFunctions: Set<string>;
  isEntryPoint: boolean;
}

export interface CallGraphBuilderOptions {
  filename?: string;
  includeArrows?: boolean; // Include arrow functions
  includeClasses?: boolean; // Include class methods
  sourceType?: 'module' | 'script' | 'unambiguous';
  plugins?: string[];
}

export class JavaScriptCallGraphBuilder {
  private callGraph: Map<string, CallGraphNode> = new Map();
  private currentFunction: string | null = null;
  private options: Required<CallGraphBuilderOptions>;

  constructor(options?: CallGraphBuilderOptions) {
    this.options = {
      filename: options?.filename ?? 'unknown.js',
      includeArrows: options?.includeArrows ?? true,
      includeClasses: options?.includeClasses ?? true,
      sourceType: options?.sourceType ?? 'module',
      plugins: options?.plugins ?? ['typescript', 'jsx'],
    };
  }

  buildFromSource(sourceCode: string): Map<string, CallGraphNode> {
    try {
      const ast = parse(sourceCode, {
        sourceType: this.options.sourceType,
        plugins: this.options.plugins as any,
      });

      traverse(ast, {
        Program: (path) => {
          // Mark exported functions as entry points
          path.traverse({
            ExportNamedDeclaration: (expPath) => {
              const decl = expPath.node.declaration;
              if (t.isFunctionDeclaration(decl) && decl.id) {
                const node = this.getOrCreateNode(decl.id.name);
                node.isEntryPoint = true;
              }
            },
            ExportDefaultDeclaration: (expPath) => {
              const decl = expPath.node.declaration;
              if (t.isFunctionDeclaration(decl) && decl.id) {
                const node = this.getOrCreateNode(decl.id.name);
                node.isEntryPoint = true;
              }
            },
          });
        },

        FunctionDeclaration: (path) => {
          if (path.node.id) {
            const funcName = path.node.id.name;
            this.getOrCreateNode(funcName, 'function', path.node.loc?.start.line);
            this.currentFunction = funcName;
            path.traverse({
              CallExpression: (callPath) => {
                this.recordCall(callPath.node);
              },
            });
            this.currentFunction = null;
          }
        },

        FunctionExpression: (path) => {
          if (path.node.id) {
            const funcName = path.node.id.name;
            this.getOrCreateNode(funcName, 'function', path.node.loc?.start.line);
            const prev = this.currentFunction;
            this.currentFunction = funcName;
            path.traverse({
              CallExpression: (callPath) => {
                this.recordCall(callPath.node);
              },
            });
            this.currentFunction = prev;
          }
        },

        ArrowFunctionExpression: (path) => {
          if (this.options.includeArrows && t.isVariableDeclarator(path.parent)) {
            const parent = path.parent as t.VariableDeclarator;
            if (t.isIdentifier(parent.id)) {
              const funcName = parent.id.name;
              this.getOrCreateNode(funcName, 'function', path.node.loc?.start.line);
              const prev = this.currentFunction;
              this.currentFunction = funcName;
              path.traverse({
                CallExpression: (callPath) => {
                  this.recordCall(callPath.node);
                },
              });
              this.currentFunction = prev;
            }
          }
        },

        ClassMethod: (path) => {
          if (this.options.includeClasses && path.node.key) {
            const className = this.getParentClassName(path);
            if (className && t.isIdentifier(path.node.key)) {
              const methodName = `${className}.${path.node.key.name}`;
              this.getOrCreateNode(methodName, 'method', path.node.loc?.start.line);
              const prev = this.currentFunction;
              this.currentFunction = methodName;
              path.traverse({
                CallExpression: (callPath) => {
                  this.recordCall(callPath.node);
                },
              });
              this.currentFunction = prev;
            }
          }
        },

        CallExpression: (path) => {
          if (this.currentFunction === null) {
            // Top-level call
            this.recordCall(path.node);
          }
        },
      });
    } catch (error) {
      console.error(`Failed to parse ${this.options.filename}:`, error);
    }

    return this.callGraph;
  }

  private recordCall(node: t.CallExpression) {
    if (!this.currentFunction) return;

    const calleeId = this.extractCallTarget(node);
    if (calleeId) {
      const caller = this.callGraph.get(this.currentFunction);
      if (caller) {
        caller.calledFunctions.add(calleeId);
        const callee = this.getOrCreateNode(calleeId);
        callee.calledByFunctions.add(this.currentFunction);
      }
    }
  }

  private extractCallTarget(node: t.CallExpression): string | null {
    if (t.isIdentifier(node.callee)) {
      return node.callee.name;
    }

    if (t.isMemberExpression(node.callee)) {
      return this.extractMemberPath(node.callee);
    }

    return null;
  }

  private extractMemberPath(node: t.MemberExpression): string {
    const parts: string[] = [];
    let current: any = node;

    while (t.isMemberExpression(current)) {
      if (t.isIdentifier(current.property)) {
        parts.unshift(current.property.name);
      } else if (t.isStringLiteral(current.property)) {
        parts.unshift(current.property.value);
      }
      current = current.object;
    }

    if (t.isIdentifier(current)) {
      parts.unshift(current.name);
    }

    return parts.join('.');
  }

  private getOrCreateNode(
    id: string,
    type: 'function' | 'method' | 'class' = 'function',
    lineNumber?: number,
  ): CallGraphNode {
    if (!this.callGraph.has(id)) {
      this.callGraph.set(id, {
        id,
        type,
        fileName: this.options.filename,
        lineNumber,
        calledFunctions: new Set(),
        calledByFunctions: new Set(),
        isEntryPoint: false,
      });
    }
    return this.callGraph.get(id)!;
  }

  private getParentClassName(path: any): string | null {
    const classPath = path.findParent((p: any) => t.isClassDeclaration(p.node));
    if (classPath && classPath.node.id) {
      return classPath.node.id.name;
    }
    return null;
  }

  getCallGraph(): Map<string, CallGraphNode> {
    return this.callGraph;
  }

  toJSON(): Record<string, any> {
    const result: Record<string, any> = {};
    for (const [key, node] of this.callGraph) {
      result[key] = {
        id: node.id,
        type: node.type,
        fileName: node.fileName,
        lineNumber: node.lineNumber,
        calledFunctions: Array.from(node.calledFunctions),
        calledByFunctions: Array.from(node.calledByFunctions),
        isEntryPoint: node.isEntryPoint,
      };
    }
    return result;
  }
}
