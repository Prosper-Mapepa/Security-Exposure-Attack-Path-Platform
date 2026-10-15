const http = require('http');
const { URL } = require('url');

const vulnerable = process.env.LAB_VULNERABLE !== 'false';
const orders = {
  '1001': { id: '1001', owner: 'alice', item: 'demo-record' },
  '1002': { id: '1002', owner: 'bob', item: 'demo-record' },
};

const server = http.createServer((req, res) => {
  res.setHeader('X-Security-Lab', 'development-only');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  const url = new URL(req.url, 'http://127.0.0.1');
  if (url.pathname === '/') {
    res.end('DEVELOPMENT SECURITY LAB. This service is for local scanner testing only.');
    return;
  }
  if (url.pathname.startsWith('/orders/')) {
    const id = url.pathname.split('/')[2];
    const order = orders[id];
    if (!order) {
      res.statusCode = 404;
      res.end('not found');
      return;
    }
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(order));
    return;
  }
  if (url.pathname === '/search') {
    const name = url.searchParams.get('name') ?? '';
    if (vulnerable && name.includes("'")) {
      res.statusCode = 500;
      res.end('database syntax error near query');
      return;
    }
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ result: 'no rows' }));
    return;
  }
  res.statusCode = 404;
  res.end('not found');
});

const host = process.env.LAB_BIND || '127.0.0.1';
server.listen(8090, host, () => {
  console.log(`DEVELOPMENT SECURITY LAB listening on ${host}:8090`);
});
