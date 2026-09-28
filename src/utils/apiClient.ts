/**
 * Secure API Client Helper
 * Handles CSRF token caching, HTTP-only cookie credentials, and error wrapping.
 */

let cachedCsrfToken: string | null = null;

/** Clears the cached CSRF token so the next request fetches a fresh one. */
export function clearCsrfToken(): void {
  cachedCsrfToken = null;
}

/**
 * Retrieves the current anti-CSRF token from the server or cookie.
 */
export async function getCsrfToken(): Promise<string> {
  if (cachedCsrfToken) return cachedCsrfToken;

  // Try reading from document.cookie
  const match = document.cookie.match(/(?:^|; )nexsus_csrf=([^;]*)/);
  if (match && match[1]) {
    cachedCsrfToken = decodeURIComponent(match[1]);
    return cachedCsrfToken;
  }

  try {
    const res = await fetch('/api/auth/csrf-token', {
      method: 'GET',
      credentials: 'include'
    });
    if (res.ok) {
      const data = await res.json();
      if (data.csrfToken) {
        cachedCsrfToken = data.csrfToken;
        return data.csrfToken;
      }
    }
  } catch (err) {
    console.warn('Failed to fetch CSRF token from server', err);
  }

  return '';
}

/**
 * Initializes the SOC operator session via cookie-based authentication.
 */
export async function initializeSession(): Promise<void> {
  try {
    // Check if current session is active
    const meRes = await fetch('/api/auth/me', {
      method: 'GET',
      credentials: 'include'
    });

    if (!meRes.ok) {
      // Bootstrap session
      await fetch('/api/auth/bootstrap', {
        method: 'POST',
        credentials: 'include'
      });
    }
    // Bootstrap (or a fresh login) issues a brand new CSRF cookie — drop any
    // cached token from a previous/invalid session so we don't keep sending
    // a value that no longer matches the current cookie.
    clearCsrfToken();
    // Prime CSRF token
    await getCsrfToken();
  } catch (e) {
    console.warn('Session initialization notice:', e);
  }
}

/**
 * Authenticated & CSRF-protected fetch wrapper.
 */
export async function secureFetch(url: string, options: RequestInit = {}): Promise<Response> {
  const method = (options.method || 'GET').toUpperCase();
  const headers: Record<string, string> = {
    ...(options.headers as Record<string, string> || {})
  };

  // Attach CSRF token for state-changing requests
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    const csrfToken = await getCsrfToken();
    if (csrfToken) {
      headers['X-CSRF-Token'] = csrfToken;
    }
  }

  try {
    const activeRole = localStorage.getItem('nexsus_user_role') || 'Admin';
    const activeUid = localStorage.getItem('nexsus_user_uid') || 'local-operator';
    const activeEmail = localStorage.getItem('nexsus_user_email') || 'operator@nexsus.local';
    if (!headers['x-nexsus-role']) headers['x-nexsus-role'] = activeRole;
    if (!headers['x-nexsus-uid']) headers['x-nexsus-uid'] = activeUid;
    if (!headers['x-nexsus-email']) headers['x-nexsus-email'] = activeEmail;
  } catch {
    // non-browser or restricted storage
  }

  return fetch(url, {
    ...options,
    credentials: 'include',
    headers
  });
}

/**
 * Same as secureFetch, but self-heals from the two most common causes of a
 * silent, repeatable request failure in this app: a stale/mismatched CSRF
 * token, or a session that was never established (or has expired). On a
 * 403 CSRF_INVALID it refreshes the token and retries once; on a 401 it
 * re-runs session bootstrap and retries once. If the retry also fails, the
 * original (post-retry) response is returned so the caller can surface the
 * real server-provided error/code to the user instead of guessing.
 */
export async function secureFetchWithRecovery(url: string, options: RequestInit = {}): Promise<Response> {
  let res = await secureFetch(url, options);
  if (res.status === 403) {
    const body = await res.clone().json().catch(() => null);
    if (body?.code === 'CSRF_INVALID') {
      clearCsrfToken();
      res = await secureFetch(url, options);
    }
  } else if (res.status === 401) {
    await initializeSession();
    res = await secureFetch(url, options);
  }
  return res;
}
