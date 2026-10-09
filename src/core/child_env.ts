/**
 * Environment for the processes Hawkeye starts (python3, mvn, gradle). They run next to code from the
 * repository being analyzed, so they get only what they need to work, never the caller's tokens and API
 * keys (HAWKEYE_API_TOKEN, ANTHROPIC_API_KEY, cloud credentials...).
 */
const BASE = [
  'PATH', 'HOME', 'USER', 'LANG', 'LC_ALL', 'TMPDIR', 'TZ',
  // Windows: without these, child processes fail to start or cannot find their profile.
  'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PATHEXT', 'TEMP', 'TMP', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA',
];
const BUILD = ['JAVA_HOME', 'GRADLE_USER_HOME', 'GRADLE_OPTS', 'MAVEN_OPTS', 'MAVEN_HOME', 'M2_HOME', 'MAVEN_ARGS'];
const PROXY = ['HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy', 'no_proxy'];

export function childEnv(kind: 'python' | 'build', source: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const keys = kind === 'build' ? [...BASE, ...BUILD, ...PROXY] : BASE;
  const env: NodeJS.ProcessEnv = {};
  for (const key of keys) if (source[key] !== undefined) env[key] = source[key];
  return env;
}
