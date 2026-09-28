import { describe, it, expect, beforeEach } from 'vitest';
import { JavaScriptCallGraphBuilder } from '../../adapters/parsers/js_typescript_parser/call_graph_builder';

describe('JavaScriptCallGraphBuilder', () => {
  let builder: JavaScriptCallGraphBuilder;

  beforeEach(() => {
    builder = new JavaScriptCallGraphBuilder();
  });

  it('should detect function declarations', () => {
    const code = `
      function foo() {
        return 42;
      }
    `;

    const graph = builder.buildFromSource(code);
    expect(graph.has('foo')).toBe(true);
    expect(graph.get('foo')?.type).toBe('function');
  });

  it('should detect function calls', () => {
    const code = `
      function foo() {
        bar();
      }

      function bar() {
        return 42;
      }
    `;

    const graph = builder.buildFromSource(code);
    const fooNode = graph.get('foo');

    expect(fooNode?.calledFunctions.has('bar')).toBe(true);
  });

  it('should detect method calls', () => {
    const code = `
      import axios from 'axios';

      function fetchData() {
        return axios.get('/api/data');
      }
    `;

    const graph = builder.buildFromSource(code);
    const fetchNode = graph.get('fetchData');

    expect(fetchNode?.calledFunctions.has('axios.get')).toBe(true);
  });

  it('should detect entry points (exports)', () => {
    const code = `
      export function publicAPI() {
        return 'hello';
      }

      function privateFunction() {
        return 'private';
      }
    `;

    const graph = builder.buildFromSource(code);
    expect(graph.get('publicAPI')?.isEntryPoint).toBe(true);
    expect(graph.get('privateFunction')?.isEntryPoint).toBe(false);
  });

  it('should handle arrow functions', () => {
    const code = `
      const asyncFetch = async () => {
        return await axios.get('/data');
      };
    `;

    const graph = builder.buildFromSource(code);
    expect(graph.has('asyncFetch')).toBe(true);
  });

  it('should handle class methods', () => {
    const code = `
      class UserService {
        getUser(id) {
          return this.fetch(\`/user/\${id}\`);
        }

        fetch(url) {
          return axios.get(url);
        }
      }
    `;

    const graph = builder.buildFromSource(code);
    expect(graph.has('UserService.getUser')).toBe(true);
    expect(graph.has('UserService.fetch')).toBe(true);
  });

  it('should convert to JSON', () => {
    const code = `
      function main() {
        helper();
      }
      function helper() {}
    `;

    const graph = builder.buildFromSource(code);
    const json = builder.toJSON();

    expect(json).toHaveProperty('main');
    expect(json).toHaveProperty('helper');
    expect(json.main.called_functions).toContain('helper');
  });
});
