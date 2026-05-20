import { describe, expect, it } from 'vitest';
import { analyzeJavaScript } from '../engine/analyzers/javascriptAnalyzer.js';

describe('api recovery', () => {
  it('recovers fetch, axios and wrapper calls with params', async () => {
    const result = await analyzeJavaScript({
      content: `
        const API = '/api';
        const USER = '/user';
        const service = axios.create({ baseURL: API });
        fetch(API + '/profile?id=' + userId, { method: 'POST', headers: { Authorization: 'Bearer abc' }, body: { uid: userId } });
        axios.post(API + USER, { uid: id, role: roleId }, { headers: { 'X-Token': token } });
        service.get(\`${'${API}'}/admin/${'${id}'}\`, { params: { verbose: true } });
      `,
    });

    expect(result.success).toBe(true);
    if (!result.success) {
      return;
    }

    expect(result.apis.map((api) => api.url)).toContain('/api/user');
    expect(result.apis.some((api) => api.url === '/api/admin/${id}' && api.method === 'GET')).toBe(true);
    expect(result.params.map((param) => param.name)).toEqual(expect.arrayContaining(['uid', 'role', 'verbose', 'id']));
    expect(result.auth).toEqual(expect.arrayContaining(['Authorization', 'X-Token']));
    expect(result.risk.some((risk) => risk.type === 'admin-api')).toBe(true);
  });

  it('recovers XMLHttpRequest open calls', async () => {
    const result = await analyzeJavaScript({
      content: `
        const xhr = new XMLHttpRequest();
        xhr.open('DELETE', '/api/internal/delete?id=1');
      `,
    });

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.apis.some((api) => api.url === '/api/internal/delete?id=1' && api.method === 'DELETE')).toBe(true);
    }
  });
});
