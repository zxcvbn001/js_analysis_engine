import { describe, expect, it } from 'vitest';
import { analyzeJavaScript } from '../engine/analyzers/javascriptAnalyzer.js';

describe('framework and legacy compatibility', () => {
  it('supports jQuery ajax, shorthand calls, XHR headers and RequireJS modules', async () => {
    const result = await analyzeJavaScript({
      content: `
        define(['jquery'], function($) {
          const BASE = '/legacy';
          $.ajax({
            url: BASE + '/user',
            type: 'POST',
            data: { uid: id },
            headers: { Authorization: 'Bearer token' }
          });
          $.get(BASE + '/list?page=1');
          var xhr = new XMLHttpRequest();
          xhr.open('GET', BASE + '/xhr/:id');
          xhr.setRequestHeader('X-Token', token);
        });
      `,
    });

    expect(result.success).toBe(true);
    if (!result.success) {
      return;
    }

    expect(result.apis.map((api) => api.url)).toEqual(expect.arrayContaining(['/legacy/user', '/legacy/list?page=1', '/legacy/xhr/:id']));
    expect(result.apis.find((api) => api.url === '/legacy/user')?.method).toBe('POST');
    expect(result.params.map((param) => param.name)).toEqual(expect.arrayContaining(['uid', 'page', 'id', 'X-Token']));
    expect(result.auth).toEqual(expect.arrayContaining(['Authorization', 'X-Token']));
  });

  it('extracts params from jQuery ajax JSON string concatenation bodies', async () => {
    const result = await analyzeJavaScript({
      content: `
        $.ajax({
          datatype: "json",
          type: "post",
          url: "/Main/LoginVal",
          contentType: 'application/json',
          data:'{"fusername":"'+$("#userid").val()+'","fpwd":"'+$("#pwd").val()+'"}'
        });
      `,
    });

    expect(result.success).toBe(true);
    if (!result.success) {
      return;
    }

    expect(result.apis.find((api) => api.url === '/Main/LoginVal')?.params).toEqual(expect.arrayContaining(['fusername', 'fpwd']));
    expect(result.params.map((param) => param.name)).toEqual(expect.arrayContaining(['fusername', 'fpwd']));
  });

  it('supports React, Next, Vite and TypeScript syntax', async () => {
    const result = await analyzeJavaScript({
      content: `
        import React from 'react';
        type UserId = string;
        const API: string = import.meta.env.VITE_API_BASE || '/api';
        export async function getServerSideProps() {
          const id: UserId = '42';
          await fetch(\`${'${API}'}/next/user/${'${id}'}\`, {
            method: 'PUT',
            headers: { Authorization: 'Bearer abc' },
            body: JSON.stringify({ role: 'admin' })
          });
          return { props: {} };
        }
        export function UserCard() {
          return <button onClick={() => axios.get(API + '/react/user')}>load</button>;
        }
      `,
    });

    expect(result.success).toBe(true);
    if (!result.success) {
      return;
    }

    expect(result.apis.map((api) => api.url)).toEqual(expect.arrayContaining(['/api/next/user/42', '/api/react/user']));
    expect(result.auth).toContain('Authorization');
  });

  it('extracts script blocks from Vue SFC content', async () => {
    const result = await analyzeJavaScript({
      content: `
        <template><button @click="load">Load</button></template>
        <script setup lang="ts">
        const API = '/vue';
        async function load() {
          await fetch(API + '/profile', { headers: { 'X-Token': token } });
        }
        </script>
      `,
    });

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.apis.map((api) => api.url)).toContain('/vue/profile');
      expect(result.auth).toContain('X-Token');
    }
  });
});
