/**
 * Project: BRS-KB (BRS XSS Knowledge Base)
 * Company: EasyProTech LLC (www.easypro.tech)
 * Dev: Brabus
 * Date: 2025-12-04 22:53:00 UTC
 * Status: Created
 * Telegram: https://t.me/easyprotech
 *
 * API service for BRS-KB Web UI
 * Provides methods for interacting with BRS-KB REST API
 */

// API base URL - can be configured via environment variable
const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8080/api';

/**
 * Fetch wrapper with error handling
 */
async function fetchAPI(endpoint, options = {}) {
  const url = `${API_BASE_URL}${endpoint}`;
  
  const defaultOptions = {
    headers: {
      'Content-Type': 'application/json',
    },
  };
  
  const response = await fetch(url, { ...defaultOptions, ...options });
  
  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Unknown error' }));
    throw new Error(error.error || `HTTP error: ${response.status}`);
  }
  
  return response.json();
}

/**
 * API service object with all endpoints
 */
const api = {
  /**
   * Get system information
   */
  getInfo: () => fetchAPI('/info'),

  /**
   * Get health status
   */
  getHealth: () => fetchAPI('/health'),

  /**
   * List all XSS contexts
   */
  listContexts: () => fetchAPI('/contexts'),

  /**
   * Get context details by ID
   * @param {string} contextId - Context identifier
   */
  getContext: (contextId) => fetchAPI(`/contexts/${contextId}`),

  /**
   * List payloads with optional filters
   * @param {Object} params - Query parameters
   * @param {string} [params.context] - Filter by context
   * @param {string} [params.severity] - Filter by severity
   * @param {boolean} [params.waf_bypass] - Filter WAF bypass payloads
   * @param {number} [params.limit] - Limit results
   * @param {number} [params.offset] - Offset for pagination
   */
  listPayloads: (params = {}) => {
    const queryString = new URLSearchParams(params).toString();
    return fetchAPI(`/payloads${queryString ? `?${queryString}` : ''}`);
  },

  /**
   * Search payloads
   * @param {string} query - Search query
   * @param {number} [limit] - Limit results
   */
  searchPayloads: (query, limit = 20) => {
    const params = new URLSearchParams({ q: query, limit: limit.toString() });
    return fetchAPI(`/payloads/search?${params}`);
  },

  /**
   * Analyze payload (GET method)
   * @param {string} payload - Payload to analyze
   */
  analyzePayload: (payload) => {
    const params = new URLSearchParams({ payload });
    return fetchAPI(`/analyze?${params}`);
  },

  /**
   * Analyze payload with options (POST method)
   * @param {string} payload - Payload to analyze
   * @param {boolean} [mlFeatures] - Include ML features
   */
  analyzePayloadPost: async (payload, mlFeatures = false) => {
    return fetchAPI('/analyze', {
      method: 'POST',
      body: JSON.stringify({ payload, ml_features: mlFeatures }),
    });
  },

  /**
   * Test payload effectiveness
   * @param {string} payloadId - Payload ID
   * @param {string} context - Context to test against
   */
  testPayload: async (payloadId, context) => {
    return fetchAPI('/test-payload', {
      method: 'POST',
      body: JSON.stringify({ payload_id: payloadId, context }),
    });
  },

  /**
   * Get recommended defenses for context
   * @param {string} context - Context identifier
   */
  getDefenses: (context) => {
    const params = new URLSearchParams({ context });
    return fetchAPI(`/defenses?${params}`);
  },

  /**
   * Get platform statistics
   */
  getStats: () => fetchAPI('/stats'),

  /**
   * Get supported languages
   */
  getLanguages: () => fetchAPI('/languages'),

  /**
   * Set current language
   * @param {string} language - Language code
   */
  setLanguage: async (language) => {
    return fetchAPI('/language', {
      method: 'POST',
      body: JSON.stringify({ language }),
    });
  },
};

export default api;
export { API_BASE_URL, fetchAPI };
