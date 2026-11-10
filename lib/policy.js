const DEFAULT_POST_SUFFIXES = Object.freeze([':list', ':tail']);

export function isReadOnlyPost(pathname, suffixes = DEFAULT_POST_SUFFIXES) {
  const lastSegment = pathname.split('/').filter(Boolean).pop() ?? '';
  return suffixes.some((suffix) => lastSegment.endsWith(suffix));
}

export function evaluate(method, pathname, { postSuffixes = DEFAULT_POST_SUFFIXES } = {}) {
  const verb = String(method ?? '').toUpperCase();

  if (verb === 'GET' || verb === 'HEAD') {
    return { allowed: true };
  }

  if (verb === 'POST' && isReadOnlyPost(pathname, postSuffixes)) {
    return { allowed: true };
  }

  return {
    allowed: false,
    reason:
      verb === 'POST'
        ? `POST is limited to read-only methods (${postSuffixes.join(', ')})`
        : `${verb || 'Unknown method'} is not a read-only HTTP method`,
  };
}

export { DEFAULT_POST_SUFFIXES };
