import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  vus: 20,
  duration: '30m',
  thresholds: {
    http_req_failed: ['rate<0.01'],
    http_req_duration: ['p(95)<500'],
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
  sleep(0.5);
}
