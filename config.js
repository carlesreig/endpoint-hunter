/* Endpoint Hunter configuration
 * This file centralizes heuristic and filtering constants.
 * It is loaded before `background.js` (see manifest.json), and exposes
 * a single global object `ENDPOINT_HUNTER_CONFIG` so values can be
 * customized or later persisted.
 */

/* eslint-disable no-var */
var ENDPOINT_HUNTER_CONFIG = ENDPOINT_HUNTER_CONFIG || {
  // Extensions to ignore (static assets)
  IGNORED_EXTENSIONS: ['.jpg', '.jpeg', '.png', '.gif', '.svg', '.webp', '.woff', '.ttf', '.m4s', '.ico'],

  // Paths considered sensitive (partial match)
  SENSITIVE_PATHS: [
    '/admin', '/api', '/auth', '/login', '/logout',
    '/token', '/user', '/users', '/account',
    '/internal', '/private', '/debug', '/phpmyadmin', '/graphql'
  ],

  // Param names considered sensitive
  SENSITIVE_PARAMS: [
    'token', 'auth', 'key', 'password', 'pwd',
    'session', 'redirect', 'jwt', 'csrf'
  ],

  // Methods considered sensitive by default
  SENSITIVE_METHODS: ['PUT', 'DELETE', 'PATCH'],

  // Tagging heuristics (params, methods, paths)
  TAG_RULES: {
    xss: {
      params: ['q', 'query', 'search', 'searchTerm', 'term', 'filter', 's', 'msg', 'comment', 'text', 'input', 'body', 'payload'],
      methods: ['GET', 'POST']
    },
    sqli: {
      params: ['id', 'user', 'uid', 'page', 'item', 'order', 'query', 'search', 'q', 'where', 'sql'],
      methods: ['GET', 'POST']
    },
    lfi: {
      params: ['file', 'path', 'template', 'include'],
      methods: ['GET']
    },
    idor: {
      params: ['id', 'user_id', 'account_id', 'order_id'],
      methods: ['GET', 'PUT', 'DELETE']
    },
    auth: {
      paths: ['/admin', '/auth', '/login', '/account', '/internal']
    }
  }
};
