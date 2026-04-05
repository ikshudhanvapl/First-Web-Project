/**
 * api.js — Typed API client.
 *
 * Stores access token in memory (NOT localStorage — XSS safe).
 * Sends token in Authorization header.
 * On 401, clears the token and redirects to login.
 */

let _accessToken = null;

export const setToken = (t) => { _accessToken = t; };
export const clearToken = () => { _accessToken = null; };
export const hasToken = () => !!_accessToken;

const BASE = '/api';

async function request(method, path, body) {
  const headers = { 'Content-Type': 'application/json' };
  if (_accessToken) headers['Authorization'] = `Bearer ${_accessToken}`;

  const res = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  if (res.status === 401) {
    clearToken();
    window.dispatchEvent(new Event('auth:expired'));
    throw new Error('Session expired');
  }

  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    throw new Error(data.detail || `HTTP ${res.status}`);
  }

  return data;
}

export const api = {
  login: (email, password) =>
    request('POST', '/auth/login', { email, password }),

  logout: () =>
    request('POST', '/auth/logout'),

  getUsers: (skip = 0, limit = 50) =>
    request('GET', `/users?skip=${skip}&limit=${limit}`),

  createUser: (payload) =>
    request('POST', '/users', payload),

  updateUser: (id, payload) =>
    request('PUT', `/users/${id}`, payload),

  deprovisionUser: (id) =>
    request('DELETE', `/users/${id}`),

  getAuditLog: () =>
    request('GET', '/audit'),
};
