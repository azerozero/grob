import http from 'k6/http';
import { check } from 'k6';

export const options = {
  stages: [
    { duration: '2m', target: 50 },
    { duration: '2m', target: 100 },
    { duration: '2m', target: 200 },
    { duration: '2m', target: 0 },
  ],
  thresholds: {
    http_req_failed: ['rate<0.1'],
  },
};

const JWT = __ENV.GROB_JWT || '';
const HOST = __ENV.GROB_HOST || 'http://127.0.0.1:13456';

const payload = JSON.stringify({
  model: 'gpt-4o',
  messages: [{ role: 'user', content: 'Hi.' }],
  max_tokens: 5,
});

export default function () {
  const res = http.post(`${HOST}/v1/chat/completions`, payload, {
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${JWT}` },
  });
  check(res, { 'not 5xx': (r) => r.status < 500 });
}
