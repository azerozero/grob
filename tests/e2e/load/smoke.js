import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  vus: 1,
  duration: '30s',
  thresholds: {
    http_req_failed: ['rate<0.01'],
    http_req_duration: ['p(95)<2000'],
  },
};

const JWT = __ENV.GROB_JWT || '';
const HOST = __ENV.GROB_HOST || 'http://127.0.0.1:13456';

const payload = JSON.stringify({
  model: 'gpt-4o',
  messages: [{ role: 'user', content: 'Hello, say hi.' }],
  max_tokens: 20,
});

export default function () {
  const res = http.post(`${HOST}/v1/chat/completions`, payload, {
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${JWT}`,
    },
  });
  check(res, {
    'status is 200': (r) => r.status === 200,
    'has choices': (r) => JSON.parse(r.body).choices !== undefined,
  });
  sleep(1);
}
