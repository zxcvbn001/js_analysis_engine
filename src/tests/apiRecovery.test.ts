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

  it('recovers request factory calls with config objects', async () => {
    const result = await analyzeJavaScript({
      content: `
        function n(e){
          return r()({url:"/indexData/getIndexList",method:"post",data:e})
        }
        const requestFactory = () => axios;
        requestFactory()({ url: "/factory/list", method: "get", params: { page: pageNo } });
      `,
    });

    expect(result.success).toBe(true);
    if (!result.success) {
      return;
    }

    expect(result.apis).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          url: '/indexData/getIndexList',
          method: 'POST',
          source: 'r()',
        }),
        expect.objectContaining({
          url: '/factory/list',
          method: 'GET',
          source: 'requestFactory()',
        }),
      ]),
    );
    expect(result.params.map((param) => param.name)).toEqual(expect.arrayContaining(['e', 'page']));
  });

  it('resolves bundled runtime baseUrl for relative request configs', async () => {
    const result = await analyzeJavaScript({
      url: 'https://grow.guosen.com.cn/ui/ep/assets/js/app.114bdb19.js',
      content: `
        var xe = document.location.protocol;
        Vue.use(plugin, {
          baseUrl: xe + ("10.118.5.54" === window.location.host ? "//10.118.5.54" : "//grow.guosen.com.cn/ep"),
          loginApi: ("10.118.5.54" === window.location.host ? "//10.118.5.54" : "//grow.guosen.com.cn/ep") + "/login"
        });
        var x = axios.create({ baseURL: "", timeout: 60000 });
        x.interceptors.request.use(function(e) {
          e.baseURL = Vue.prototype.pluginParams.baseUrl;
          return e;
        });
        function login(e) {
          return o()({ url: "/login", method: "post", data: e });
        }
      `,
    });

    expect(result.success).toBe(true);
    if (!result.success) {
      return;
    }

    expect(result.apis).toContainEqual(
      expect.objectContaining({
        url: '/login',
        resolvedUrl: 'https://grow.guosen.com.cn/ep/login',
        baseUrl: 'https://grow.guosen.com.cn/ep',
        confidence: 'high',
      }),
    );
  });
});
