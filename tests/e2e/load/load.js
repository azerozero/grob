import http from 'k6/http';
import { check } from 'k6';

export const options = {
  stages: [
    { duration: '1m', target: 10 },
    { duration: '3m', target: 50 },
    { duration: '1m', target: 0 },
  ],
  thresholds: {
    http_req_failed: ['rate<0.05'],
    http_req_duration: ['p(95)<1000', 'p(99)<2000'],
  },
};

const JWT = __ENV.GROB_JWT || '';
const HOST = __ENV.GROB_HOST || 'http://127.0.0.1:13456';

const payload = JSON.stringify({
  model: 'gpt-4o',
  messages: [{ role: 'user', content: 'Hello.' }],
  max_tokens: 10,
  temperature: 0,
});

export default function () {
  const res = http.post(`${HOST}/v1/chat/completions`, payload, {
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${JWT}` },
  });
  check(res, { 'status 200': (r) => r.status === 200 });
}
