'use strict';
// vca-hub の OLDP の待ち受けを、乱数で作った入力で叩く。
//   node --expose-gc tools/fuzz-hub.js [回数の倍率]
// vca-hub はこのプロセスの中で動かす。捕まえていない例外や Promise の拒否が起きたら、失敗として数える。
//   A. ハンドシェイクの前(TCP): 乱数のバイト列、長さの合わないフレーム、知らない種類、壊したハンドシェイク
//   B. ハンドシェイクの前(TCP の上の UART): 乱数のバイト列、壊した COBS・CRC、ACK
//   C. ペアリングした機器が、形の崩れたメッセージを正しく暗号化して送る(壊れた機器・乗っ取られた機器)
//   D. ペアリングした機器が、続きのフラグの付いたメッセージを多くのリクエスト ID で送り、ホストのメモリがどれだけ増えるか
//   E. ハンドシェイクを始めない接続を上限の数だけ開いたまま、正しい機器がつなげるか
//   F. 管理画面のペアリングの操作を、別のサイト・別の Host 名・この PC の外から行えないこと
// 最後に、正しい機器の PUT が通ることを確かめる。

const crypto = require('node:crypto');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');

const EXT_ROOT = path.join(__dirname, '..');
const { root: ROOT } = require('../oldp/reference.js');
const HUB = process.env.OLDP_VCA_HUB || path.join(EXT_ROOT, '..', 'vca-hub');
const { loadConfig, merge } = require(path.join(HUB, 'src', 'config.js'));
const { createHub } = require(path.join(HUB, 'src', 'app.js'));
const P = require(path.join(ROOT, 'js', 'src', 'index.js'));
const { TYPES, VERSION, uartEncode } = P;

const scale = Number(process.argv[2] || 1);
let failed = 0, crashes = 0;
process.on('uncaughtException', e => { crashes++; console.log('捕まえていない例外:', e && e.stack); });
process.on('unhandledRejection', e => { crashes++; console.log('捕まえていない Promise の拒否:', e && e.stack); });
function check(name, ok, detail) {
  console.log(`${ok ? 'OK' : 'NG'}  ${name}${detail !== undefined ? `  [${detail}]` : ''}`);
  if (!ok) failed++;
}
const wait = ms => new Promise(r => setTimeout(r, ms));
const rnd = n => crypto.randomInt(n);
const framed = f => Buffer.concat([Buffer.from([(f.length >> 8) & 0xff, f.length & 0xff]), f]);
const LABELS = ['JOB', 'STATUS', 'TRCFMT', 'R', 'A', 'DBL', 'HBOX', 'ETYP', 'TIME', 'EXT', 'ACME.X', 'IGNORED', 'REJECTED', 'EVENT', 'TEXT', 'LABELS', 'DO', 'SPH'];
function junkLines() {
  const out = [];
  for (let k = 1 + rnd(30); k--;) {
    const w = rnd(12);
    if (w === 0) out.push(crypto.randomBytes(rnd(120)).toString('latin1'));
    else if (w === 1) out.push('='.repeat(rnd(5)) + 'X'.repeat(rnd(100)));
    else if (w === 2) out.push(`TRCFMT=1;${rnd(2) ? 99999999 : rnd(5000)};${rnd(2) ? 'E' : 'U'};R;F`);
    else if (w === 3) out.push('R=' + Array.from({ length: rnd(40) }, () => String(rnd(2) ? rnd(99999999) : -rnd(100))).join(';'));
    else if (w === 4) out.push(`EXT=${['ACME', 'OLDPKEY', 'X'.repeat(rnd(70))][rnd(3)]}`);
    else out.push(`${LABELS[rnd(LABELS.length)]}=${Array.from({ length: rnd(6) }, () => crypto.randomBytes(rnd(12)).toString('base64')).join(';')}`);
  }
  return Buffer.from(out.join(rnd(5) ? '\r\n' : '\n') + (rnd(3) ? '\r\n' : ''), 'latin1');
}

function rawConn(port, chunks, closeAfter = 50) {
  return new Promise(resolve => {
    const s = net.connect(port, '127.0.0.1');
    s.on('error', () => {});
    s.on('data', () => {});
    s.on('close', resolve);
    s.on('connect', async () => {
      for (const c of chunks) { if (s.destroyed) break; s.write(c); if (rnd(4) === 0) await wait(rnd(5)); }
      setTimeout(() => s.destroy(), closeAfter);
    });
  });
}

async function main() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'oldp-fuzz-hub-'));
  const cfg = merge(loadConfig(path.join(dir, 'none.json')), {
    dataDir: path.join(dir, 'data'), web: { enabled: true, host: '127.0.0.1', port: 0 }, remote: { enabled: false }, connectDelay: 0,
    extensionsDir: EXT_ROOT, extensions: { 'oldp': true },
    listeners: [{ name: 'tcp', port: 0, protocol: 'oldp' }, { name: 'uart', port: 0, protocol: 'oldp', settings: { transport: 'uart' } }],
  });
  const hub = createHub(cfg);
  const ports = await hub.start();
  const ext = hub.ext.get('oldp');
  const route = (m, p) => ext.routes.find(r => r.method === m && r.path === p).handler;
  const devKeys = P.noise.keyPair();
  const caps = [['VER', '1.0'], ['DEV', 'EDG'], ['VEN', 'FUZZ'], ['MODEL', 'F'], ['MAXFRAME', '4096'], ['EXT', 'ACME']];
  const connectDev = () => P.connect('127.0.0.1', ports.listeners.tcp, { keys: devKeys, caps, trust: () => true, timeoutMs: 3000 });
  const mem = () => { if (global.gc) global.gc(); return process.memoryUsage().heapUsed + process.memoryUsage().arrayBuffers; };

  try {
    // ペアリング
    await connectDev().catch(() => {});
    route('POST', 'trust')({ body: { fingerprint: P.noise.fingerprint(devKeys.publicKey) } });

    // A. ハンドシェイクの前(TCP)
    const nA = 2000 * scale;
    const t0 = Date.now();
    for (let i = 0; i < nA; i += 20) {
      await Promise.all(Array.from({ length: 20 }, () => {
        const chunks = [];
        for (let k = 1 + rnd(5); k--;) {
          const w = rnd(8);
          if (w === 0) chunks.push(crypto.randomBytes(rnd(300)));
          else if (w === 1) chunks.push(Buffer.from([rnd(256), rnd(256)]));                                   // 長さだけ
          else if (w === 2) chunks.push(framed(Buffer.from([rnd(256), rnd(256), ...crypto.randomBytes(rnd(100))])));
          else if (w === 3) chunks.push(framed(Buffer.concat([Buffer.from([VERSION, TYPES.hs1]), crypto.randomBytes(rnd(2) ? 32 : rnd(80))])));
          else if (w === 4) chunks.push(framed(Buffer.concat([Buffer.from([VERSION, TYPES.hs3]), crypto.randomBytes(rnd(200))])));
          else if (w === 5) chunks.push(framed(Buffer.concat([Buffer.from([VERSION, TYPES.data]), crypto.randomBytes(rnd(200))])));
          else if (w === 6) chunks.push(framed(Buffer.concat([Buffer.from([VERSION, TYPES.fail]), crypto.randomBytes(rnd(20))])));
          else chunks.push(Buffer.from([0xff, 0xff, ...crypto.randomBytes(rnd(1000))]));
        }
        return rawConn(ports.listeners.tcp, chunks);
      }));
    }
    check(`A. TCP のハンドシェイクの前に壊れたものを ${nA} 接続で送っても、ホストは止まらない`, crashes === 0, `${((Date.now() - t0) / 1000).toFixed(1)} 秒`);

    // B. ハンドシェイクの前(UART)
    const nB = 1000 * scale;
    for (let i = 0; i < nB; i += 20) {
      await Promise.all(Array.from({ length: 20 }, () => {
        const chunks = [];
        for (let k = 1 + rnd(6); k--;) {
          const w = rnd(6);
          if (w === 0) chunks.push(crypto.randomBytes(rnd(400)));
          else if (w === 1) chunks.push(uartEncode(rnd(3), rnd(256), Buffer.from([rnd(256), rnd(256), ...crypto.randomBytes(rnd(100))])));
          else if (w === 2) chunks.push(uartEncode(0, rnd(256), Buffer.concat([Buffer.from([VERSION, TYPES.hs1]), crypto.randomBytes(32)])));
          else if (w === 3) { const u = uartEncode(0, rnd(256), Buffer.from([VERSION, TYPES.data, 1, 2, 3])); u[rnd(u.length - 1)] ^= 1 << rnd(8); chunks.push(u); }
          else if (w === 4) chunks.push(uartEncode(1, rnd(256)));
          else chunks.push(Buffer.alloc(rnd(50)));
        }
        return rawConn(ports.listeners.uart, chunks, 30);
      }));
    }
    check(`B. UART のハンドシェイクの前に壊れたものを ${nB} 接続で送っても、ホストは止まらない`, crashes === 0);

    // C. ペアリングした機器の、形の崩れたメッセージ
    const nC = 100 * scale;
    let answered = 0, sent = 0, closedByHost = 0;
    for (let i = 0; i < nC; i++) {
      let dev;
      try { dev = await connectDev(); } catch { continue; }
      const closed = new Promise(r => dev.once('error', r));
      for (let k = 0; k < 20; k++) {
        const op = [1, 2, 3, 4, 5, 6, 7, 8, 0x80, 0x90, 0, 0xff][rnd(12)];
        const flags = rnd(4) ? 0 : rnd(256);
        const id = rnd(4) ? 1 + rnd(100) : rnd(65536);
        const body = rnd(10) ? junkLines() : Buffer.from('A'.repeat(rnd(2) ? 81 : 70000), 'ascii');
        sent++;
        const w = new Promise(r => {
          const t = setTimeout(() => r(false), 300);
          const on = f => { clearTimeout(t); r(true); };
          dev.link.once('frame', on);
        });
        try { await dev.sendMessage(op, id, flags, body); } catch { break; }
        if (await w) answered++;
        if (dev.closed) { closedByHost++; break; }
      }
      dev.close();
      await Promise.race([closed, wait(10)]);
    }
    check(`C. ペアリングした機器が形の崩れたメッセージを ${sent} 個送っても、ホストは止まらない`, crashes === 0, `応答のあったもの ${answered}、ホストが閉じたセッション ${closedByHost}`);

    // D. 続きのフラグの付いたメッセージを、多くのリクエスト ID で
    {
      const dev = await connectDev();
      const before = mem();
      const ids = 400 * scale, per = 200 * 1024;
      const chunk = Buffer.from(('R=' + '2400;'.repeat(14) + '2400\r\n').repeat(40), 'ascii');   // 約 3 KB
      let bytes = 0;
      try {
        for (let id = 1; id <= ids; id++) {
          for (let b = 0; b < per; b += chunk.length) { await dev.sendMessage(P.OPS.PUT, id, 1, chunk); bytes += chunk.length; }
        }
      } catch (e) { console.log('    (送る途中で閉じられた:', e.message, ')'); }
      await wait(500);
      const grown = mem() - before;
      console.log(`    (続きのフラグの付いたメッセージを ${ids} 個のリクエスト ID で計 ${(bytes / 1048576).toFixed(0)} MiB 送り、ホストのメモリは ${(grown / 1048576).toFixed(0)} MiB 増えた)`);
      check('D. 終わらないメッセージを多くのリクエスト ID で送っても、ホストのメモリは送った量に比例して増えない', grown < bytes / 4, `${(grown / 1048576).toFixed(0)} MiB / ${(bytes / 1048576).toFixed(0)} MiB`);
      dev.close();
      await wait(3000);
      mem();
      const after = mem() - before;
      console.log(`    (接続を閉じて 3 秒後の増え方: ${(after / 1048576).toFixed(0)} MiB。機器の側もこのプロセスの中にある)`);
      check('D. 接続を閉じた後に、ためたものが残らない', after < 16 * 1048576, `${(after / 1048576).toFixed(0)} MiB`);
    }

    // E. ハンドシェイクを始めない接続を上限の数だけ開いておく
    {
      const idle = [];
      for (let i = 0; i < 8; i++) { const s = net.connect(ports.listeners.tcp, '127.0.0.1'); s.on('error', () => {}); idle.push(s); }
      await wait(300);
      const t = Date.now();
      const r = await connectDev().then(() => 'つながった', e => `つながらない(${e.code || e.message})`);
      console.log(`    (ハンドシェイクを始めない接続 8 つを開いたまま、正しい機器: ${r}、${((Date.now() - t) / 1000).toFixed(1)} 秒)`);
      check('E. ハンドシェイクを始めない接続が上限に達している間は、新しい接続を鍵の計算の前に閉じる(規格 4 章)', r !== 'つながった');
      for (const s of idle) s.destroy();
      await wait(300);
      const r2 = await connectDev().then(d => { d.close(); return 'つながった'; }, e => `つながらない(${e.code || e.message})`);
      check('E. その接続が閉じられると、正しい機器はつながる', r2 === 'つながった', r2);
    }

    // F. 管理画面のペアリングの操作(信じる)を、外から行えないこと
    {
      const http = require('node:http');
      const req = (host, headers, method = 'POST', p = '/api/ext/oldp/trust', body = '{"fingerprint":"AAAA-AAAA-AAAA-AAAA"}') => new Promise(resolve => {
        const r = http.request({ host, port: ports.web, method, path: p, headers: { 'Content-Type': 'application/json', ...headers } }, res => { res.resume(); resolve(res.statusCode); });
        r.on('error', e => resolve(e.code));
        if (method !== 'GET') r.write(body);
        r.end();
      });
      const noHeader = await req('127.0.0.1', {});
      check('F. 独自ヘッダーの無い POST(別のサイトのフォームなど)では、ペアリングを操作できない', noHeader === 403, noHeader);
      const evilHost = await req('127.0.0.1', { Host: 'attacker.example', 'X-VCA-Hub': '1' });
      check('F. Host が localhost でない要求(DNS リバインディング)は断る', evilHost === 403, evilHost);
      const evilGet = await req('127.0.0.1', { Host: 'attacker.example' }, 'GET', '/api/ext/oldp/peers');
      check('F. Host が localhost でない要求では、ペアリングの一覧も読めない', evilGet === 403, evilGet);
      const lanIp = Object.values(os.networkInterfaces()).flat().find(a => a && a.family === 'IPv4' && !a.internal);
      if (lanIp) {
        const fromLan = await req(lanIp.address, { 'X-VCA-Hub': '1' }, 'GET', '/api/ext/oldp/peers');
        check('F. 管理画面は、この PC の外向きのアドレスでは待ち受けない', typeof fromLan === 'string', `${lanIp.address}: ${fromLan}`);
      }
    }

    // 最後: 正しい機器の PUT
    const dev = await connectDev();
    const res = await dev.request('PUT', [['JOB', 'FUZZ-END'], ['DBL', '18.00']]);
    dev.close();
    check('最後に、正しい機器の PUT が通る', res.status === 0, `STATUS=${res.status}`);
    check('捕まえていない例外・Promise の拒否が起きなかった', crashes === 0, crashes);
  } finally {
    await hub.stop();
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  }
  console.log(failed ? `失敗 ${failed} 件` : 'すべて通った');
  process.exit(failed ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(2); });
