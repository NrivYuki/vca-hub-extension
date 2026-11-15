'use strict';
// TCP の線に割り込む相手を置いて、機器の側の実装(C の模擬機器、または H8 の基板の LAN)と vca-hub の動作を確かめる。
//   node tools/attack-tcp.js sim
//   node tools/attack-tcp.js h8lan [COM11]   基板の ip コマンドで、この PC のアドレスとポート 33520 を設定しておく
// 機器と vca-hub の TCP の待ち受けの間に、この道具の中継を挟む。中継は線の上のフレームを全て見て、
// 差し込み・書き換え・送り直し・捨てること、接続を切ることができる。線の上のバイトに、平文や静的な公開鍵が現れないかも調べる。

const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');

const EXT_ROOT = path.join(__dirname, '..');
const { root: ROOT } = require('../oldp/reference.js');
const HUB = process.env.OLDP_VCA_HUB || path.join(EXT_ROOT, '..', 'vca-hub');
if (!fs.existsSync(path.join(HUB, 'src', 'app.js'))) { console.error(`vca-hub が見つかりません(${HUB})`); process.exit(2); }
const { loadConfig, merge } = require(path.join(HUB, 'src', 'config.js'));
const { createHub } = require(path.join(HUB, 'src', 'app.js'));
const { TYPES, VERSION } = require(path.join(ROOT, 'js', 'src', 'frame.js'));
const { fingerprint } = require(path.join(ROOT, 'js', 'src', 'noise.js'));

const target = process.argv[2] || 'sim';
const comPort = process.argv[3] || 'COM11';
const isBoard = target === 'h8lan';
const LAN_PORT = 33520;

let failed = 0;
function check(name, ok, detail) {
  console.log(`${ok ? 'OK' : 'NG'}  ${name}${detail !== undefined ? `  [${detail}]` : ''}`);
  if (!ok) failed++;
}
const logValue = (log, key) => { const m = new RegExp(`(?:^|\\s)${key}=(\\S*)`).exec(log); return m ? m[1] : undefined; };
const wait = ms => new Promise(r => setTimeout(r, ms));
const framed = f => Buffer.concat([Buffer.from([f.length >> 8, f.length & 0xff]), f]);

// ---- 線に割り込む中継 ----
function startProxy(port, host) {
  let attack = null, ctx = {}, upstream = 0;
  const before = x => (typeof attack === 'function' ? attack.call(ctx, x) : null);
  const after = x => { if (attack && typeof attack.after === 'function') attack.after.call(ctx, x); };
  const server = net.createServer(dev => {
    const hub = net.connect(upstream, '127.0.0.1');
    const st = { fromDev: [], fromHost: [], wire: [], log: [], closedBy: null };
    const send = { toDev: b => dev.write(b), toHost: b => hub.write(b) };
    const inject = (dir, frame) => { send[dir](framed(frame)); st.log.push(`${dir} に差し込み(${frame.length})`); };
    const raw = (dir, bytes) => { send[dir](bytes); st.log.push(`${dir} にバイト列(${bytes.length})`); };
    const cut = () => { st.log.push('接続を切った'); dev.destroy(); hub.destroy(); };
    const pipe = (from, dir, list) => {
      let buf = Buffer.alloc(0);
      from.on('data', chunk => {
        st.wire.push(chunk);
        buf = Buffer.concat([buf, chunk]);
        while (buf.length >= 2) {
          const n = buf.readUInt16BE(0);
          if (buf.length < 2 + n) break;
          const body = buf.subarray(2, 2 + n);
          buf = buf.subarray(2 + n);
          const f = { body: Buffer.from(body), type: body[1], index: list.length };
          list.push(f);
          const act = before({ dir, f, st, inject, raw, cut });
          if (act === 'drop') { st.log.push(`${dir} のフレームを捨てた(種類 ${f.type})`); continue; }
          if (act === 'cut') { cut(); return; }
          if (Buffer.isBuffer(act)) { send[dir](framed(act)); st.log.push(`${dir} のフレームを書き換えた`); continue; }
          send[dir](framed(f.body));
          after({ dir, f, st, inject, raw, cut });
        }
      });
    };
    pipe(dev, 'toHost', st.fromDev);
    pipe(hub, 'toDev', st.fromHost);
    dev.on('close', () => { st.closedBy = st.closedBy || 'dev'; hub.destroy(); });
    hub.on('close', () => { st.closedBy = st.closedBy || 'host'; dev.destroy(); });
    dev.on('error', () => {}); hub.on('error', () => {});
    server.last = st;
  });
  return new Promise(resolve => server.listen(port, host, () => resolve({
    port: server.address().port,
    set(a, up) { attack = a; ctx = {}; server.last = null; upstream = up; },
    get last() { return server.last; },
    close: () => server.close(),
  })));
}

// ---- 機器の操作 ----
function collect(child) { let out = ''; child.stdout.on('data', d => { out += d.toString('utf8'); }); child.stderr.on('data', d => { out += d.toString('utf8'); }); return () => out; }
const SIM_PORT = 35900 + (process.pid % 90);
function simRun(port, cmd, { pair = false, state }) {
  return new Promise((resolve, reject) => {
    const args = ['-e', 'c/sim_device', cmd, '--listen', String(SIM_PORT), '--state', state, '--file', 'samples/frame-right.vca'];
    if (pair) args.push('--pair');
    const child = spawn('wsl', args, { cwd: ROOT });
    const text = collect(child);
    const limit = setTimeout(() => child.kill(), 240000);
    let tries = 0;
    const bridge = () => {
      const a = net.connect(SIM_PORT, '127.0.0.1');
      a.once('error', () => { if (++tries > 60) { child.kill(); return; } setTimeout(bridge, 500); });
      a.once('connect', () => {
        const b = net.connect(port, '127.0.0.1');
        a.pipe(b); b.pipe(a);
        a.removeAllListeners('error');
        for (const s of [a, b]) s.on('error', () => { a.destroy(); b.destroy(); });
        b.on('close', () => a.destroy());
      });
    };
    const timer = setInterval(() => { if (!text().includes('LISTENING')) return; clearInterval(timer); bridge(); }, 100);
    child.on('error', reject);
    child.on('close', () => {
      clearInterval(timer); clearTimeout(limit);
      const m = /OLDP-END (-?\d+) (-?\d+)\r?\n(.*)/.exec(text());
      if (!m) return reject(new Error(`模擬機器の結果がありません: ${text()}`));
      resolve({ rc: Number(m[1]), status: Number(m[2]), log: m[3] });
    });
  });
}
function pwsh(args) {
  return new Promise((resolve, reject) => {
    const child = spawn('pwsh', ['-NoProfile', '-File', ...args], { cwd: ROOT });
    const text = collect(child);
    child.on('error', reject);
    child.on('close', code => resolve({ code, out: text() }));
  });
}
async function h8Command(cmd) {
  const r = await pwsh(['tools/h8-session.ps1', '-Port', comPort, '-Command', cmd]);
  if (r.code) throw new Error(`基板が応えません(${cmd}): ${r.out}`);
  return r.out.trim();
}
async function h8Run(cmd, { pair = false } = {}) {
  const a = ['tools/h8-session.ps1', '-Port', comPort, '-Command', cmd, '-Lan'];
  if (pair) a.push('-Pair');
  const r = await pwsh(a);
  const log = r.out.trim().split(/\r?\n/).filter(l => / rc=/.test(l)).pop() || '';
  if (!log) throw new Error(`基板の結果がありません: ${r.out}`);
  return { rc: Number(logValue(log, 'rc')), status: Number(logValue(log, 'status')), log };
}

// ---- 攻撃に使うもの ----
const failFrame = code => Buffer.from([VERSION, TYPES.fail, code]);
const isData = f => f.type === TYPES.data;
const flipped = body => { const b = Buffer.from(body); b[b.length - 20] ^= 0x01; return b; };
// 位数の小さい点(X25519 の結果が全て 0 になる)
const LOW_ORDER = Buffer.from('e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800', 'hex');

// ---- 位数の小さい点を使って、ハンドシェイクを最後まで計算する相手 ----
// 相手の X25519 の結果が全て 0 になるように作った鍵でも、暗号文は正しく作れる。全て 0 を確かめない実装は、
// その先のペアリングの確認まで進み、理由 3 で断る。確かめる実装は、理由 2 で断る(規格 6 章)。
const P = require(path.join(ROOT, 'js', 'src', 'index.js'));
const PROLOGUE = Buffer.from('optical-lab-device-protocol 1', 'ascii');
class Sym {
  constructor() { this.h = Buffer.from('Noise_XX_25519_ChaChaPoly_SHA256', 'ascii'); this.ck = Buffer.from(this.h); this.k = null; this.n = 0n; this.mixHash(PROLOGUE); }
  mixHash(d) { this.h = crypto.createHash('sha256').update(Buffer.concat([this.h, d])).digest(); }
  mixKey(ikm) { [this.ck, this.k] = P.noise.hkdf2(this.ck, ikm); this.n = 0n; }
  enc(pt) { const c = P.noise.aeadEncrypt(this.k, this.n++, this.h, pt); this.mixHash(c); return c; }
  dec(ct) { const p = P.noise.aeadDecrypt(this.k, this.n++, this.h, ct); this.mixHash(ct); return p; }
}
const ZERO = Buffer.alloc(32);
const capsOf = dev => Buffer.from(P.records.format([['VER', '1.0'], ['DEV', dev], ['VEN', 'ATTACK'], ['MODEL', 'Z'], ['MAXFRAME', '512']]), 'ascii');
function readFrames(sock, onFrame) {
  let buf = Buffer.alloc(0);
  sock.on('data', d => {
    buf = Buffer.concat([buf, d]);
    while (buf.length >= 2 && buf.length >= 2 + buf.readUInt16BE(0)) {
      const f = buf.subarray(2, 2 + buf.readUInt16BE(0)); buf = buf.subarray(2 + f.length); onFrame(Buffer.from(f));
    }
  });
}
// ホストの代わり: 一時鍵を位数の小さい点にし、ee を全て 0 として 2 つ目のメッセージを作る。
// low が false なら、正しい一時鍵で同じことをする(比べるため。機器は、知らないホストとして理由 3 で断る)
function zeroHost(low = true) {
  const s = P.noise.keyPair();
  let reply = null;
  const server = net.createServer(sock => {
    sock.on('error', () => {});
    readFrames(sock, f => {
      if (f[1] === TYPES.hs1) {
        const re = f.subarray(2, 34), ss = new Sym(), e = P.noise.keyPair();
        const ePub = low ? LOW_ORDER : e.publicKey;
        ss.mixHash(re); ss.mixHash(Buffer.alloc(0));                    // e と、1 つ目のメッセージの空の payload
        ss.mixHash(ePub); ss.mixKey(low ? ZERO : P.noise.dh(e, re));    // e, ee(low なら全て 0)
        const sct = ss.enc(s.publicKey); ss.mixKey(P.noise.dh(s, re));   // s, es
        const body = Buffer.concat([Buffer.from([VERSION, TYPES.hs2]), ePub, sct, ss.enc(capsOf('HST'))]);
        sock.write(framed(body));
      } else if (!reply) reply = f;
    });
  });
  return new Promise(r => server.listen(0, '127.0.0.1', () => r({ port: server.address().port, reply: () => reply, close: () => server.close() })));
}
// 機器の代わり: 静的な公開鍵を位数の小さい点にし、se を全て 0 として 3 つ目のメッセージを作る。
// low が false なら、正しい静的な鍵で同じことをする(比べるため。ホストは、ペアリングしていない機器として理由 3 で断る)
function zeroDevice(port, low = true) {
  return new Promise((resolve, reject) => {
    const e = P.noise.keyPair(), ss = new Sym(), s = P.noise.keyPair();
    const sock = net.connect(port, '127.0.0.1');
    let step = 0, reply = null;
    sock.on('error', reject);
    sock.on('close', () => resolve(reply));
    readFrames(sock, f => {
      if (step === 0 && f[1] === TYPES.hs2) {
        step = 1;
        try { finish(f); } catch (err) { reply = Buffer.from(`解けない 2 つ目のメッセージ(${f.length} バイト): ${err.message}`); sock.destroy(); }
      } else if (!reply) reply = f;
    });
    function finish(f) {
        const m = f.subarray(2), re = m.subarray(0, 32);
        ss.mixHash(re); ss.mixKey(P.noise.dh(e, re));
        const rs = ss.dec(m.subarray(32, 80)); ss.mixKey(P.noise.dh(e, rs));
        ss.dec(m.subarray(80));
        const sct = ss.enc(low ? LOW_ORDER : s.publicKey);              // s(low なら位数の小さい点)
        ss.mixKey(low ? ZERO : P.noise.dh(s, re));                      // se(low なら全て 0)
        sock.write(framed(Buffer.concat([Buffer.from([VERSION, TYPES.hs3]), sct, ss.enc(capsOf('EDG'))])));
    }
    ss.mixHash(e.publicKey); ss.mixHash(Buffer.alloc(0));               // e と、1 つ目のメッセージの空の payload
    sock.write(framed(Buffer.concat([Buffer.from([VERSION, TYPES.hs1]), e.publicKey])));
  });
}

// 線の上の全てのバイトから、32 バイトの並びごとにフィンガープリントを求め、静的な公開鍵が現れないかを調べる
function keysOnWire(wire, fps) {
  const all = Buffer.concat(wire);
  const found = new Set();
  for (let i = 0; i + 32 <= all.length; i++) {
    const fp = fingerprint(all.subarray(i, i + 32));
    if (fps.includes(fp)) found.add(fp);
  }
  return [...found];
}

async function newHub(dir, name) {
  const cfg = merge(loadConfig(path.join(dir, 'none.json')), {
    dataDir: path.join(dir, name), web: { enabled: false }, remote: { enabled: false }, connectDelay: 0,
    extensionsDir: EXT_ROOT, extensions: { 'oldp': true },
    listeners: [{ name: 'tcp', port: 0, protocol: 'oldp' }],
  });
  const hub = createHub(cfg);
  const ports = await hub.start();
  const ext = hub.ext.get('oldp');
  const route = (m, p) => ext.routes.find(r => r.method === m && r.path === p).handler;
  return { hub, port: ports.listeners.tcp, route };
}

async function main() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'oldp-attack-tcp-'));
  const A = await newHub(dir, 'a');          // 本物のホスト
  const B = await newHub(dir, 'b');          // なりすましのホスト(別の鍵)
  const hostFp = A.route('GET', 'peers')({}).host;
  const proxy = await startProxy(isBoard ? LAN_PORT : 0, isBoard ? '0.0.0.0' : '127.0.0.1');
  const STATE = `/tmp/oldp-attack-tcp-${process.pid}`;
  const runRaw = (cmd, o = {}) => (isBoard ? h8Run(cmd, o) : simRun(proxy.port, cmd, { state: STATE, ...o }));
  const run = async (attack, cmd, o = {}) => {
    proxy.set(attack, o.upstream || A.port);
    const t0 = Date.now();
    const r = await runRaw(cmd, o);
    await wait(300);
    r.sec = ((Date.now() - t0) / 1000).toFixed(1); r.st = proxy.last;
    return r;
  };
  const stored = () => A.hub.store.list().length;
  const seed = (job, name) => {
    const body = fs.readFileSync(path.join(ROOT, 'samples', 'frame-both.vca'), 'latin1').replace('REQ=FIL', 'ANS=TRC').replace(/^JOB=.*$/m, `JOB=${job}`);
    const e = A.hub.store.saveReceived({ body, type: 'TRC', job, peer: 'attack', crcOk: null });
    A.hub.store.queue(e.id, name);
    return e.id;
  };
  const brief = r => `${r.sec} 秒 rc=${r.rc} status=${r.status} fail=${logValue(r.log, 'fail')}${r.st ? ' ' + r.st.log.join('、') : ''}`;
  console.log(`対象: ${target}  ホスト ${hostFp}`);

  try {
    if (isBoard) await h8Command('unpair');
    await run(null, 'put P-1', { pair: true });
    const devFp = Object.keys(A.route('GET', 'peers')({}).pending)[0];
    A.route('POST', 'trust')({ body: { fingerprint: devFp } });

    // 0. 割り込まないとき。線の上に平文と静的な公開鍵が現れないこと
    const secretJob = 'SECRET-JOB-7QX';
    const id0 = seed(secretJob, 'Q-0');
    let r = await run(null, 'get Q-0');
    check('割り込まないとき、GET と RESULT が通る', r.rc === 0 && r.status === 0 && A.hub.store.get(id0).status === 'sent', brief(r));
    let wire = Buffer.concat(r.st.wire).toString('latin1');
    const plain = ['JOB=', secretJob, 'VER=', 'DEV=', 'MODEL=', 'MAXFRAME', 'TRCFMT', 'R=', 'STATUS='].filter(s => wire.includes(s));
    check('線の上に、ジョブ・ケイパビリティ・結果の平文が現れない', plain.length === 0, plain.join(' ') || `${wire.length} バイトを調べた`);
    const keys = keysOnWire(r.st.wire, [hostFp, devFp]);
    check('線の上に、機器とホストの静的な公開鍵がそのまま現れない', keys.length === 0, keys.join(' ') || '32 バイトの並びを全て調べた');
    const sizes = r.st.fromHost.filter(isData).map(f => f.body.length);
    console.log(`    (ホストからのデータのフレームの長さ: ${sizes.join(' ')}。暗号文の長さは中身の長さを表す)`);
    const oldHostData = r.st.fromHost.filter(isData).map(f => f.body);

    // 1. ホストの応答を 1 ビット書き換える
    r = await run(x => (x.dir === 'toDev' && isData(x.f) && x.st.fromHost.filter(isData).length === 2 ? flipped(x.f.body) : null), 'put A-1');
    check('書き換えた応答を、機器は受け入れずに接続を閉じる', r.rc === -4, brief(r));

    // 2. 機器の要求を 1 ビット書き換える
    let n = stored();
    r = await run(x => (x.dir === 'toHost' && isData(x.f) && x.f.index === 2 ? flipped(x.f.body) : null), 'put A-2');
    check('書き換えた要求を、ホストは受け入れずに接続を閉じる', r.rc !== 0 && stored() === n && r.st.closedBy === 'host', brief(r));

    // 3. 機器の要求を 2 度送る(同じセッションの送り直し)
    n = stored();
    r = await run({ after(x) { if (x.dir === 'toHost' && isData(x.f) && x.f.index === 2) x.inject('toHost', x.f.body); } }, 'put A-3');
    check('同じ要求を 2 度送っても、ホストは 2 度目を受け入れない(閉じる)', stored() <= n + 1 && r.st.closedBy === 'host', brief(r));

    // 4. 前のセッションの受け入れの通知に置き換える
    r = await run(x => (x.dir === 'toDev' && isData(x.f) && x.st.fromHost.filter(isData).length === 1 ? oldHostData[0] : null), 'put A-4');
    check('前のセッションの受け入れの通知を、機器は受け入れない', r.rc === -4, brief(r));

    // 5. ハンドシェイクの 1 つ目のバージョンを書き換える
    r = await run(x => { if (x.dir === 'toHost' && x.f.type === TYPES.hs1) { const b = Buffer.from(x.f.body); b[0] = 2; return b; } return null; }, 'put A-5');
    check('バージョンの違うフレームに、ホストは失敗(理由 1)を返して閉じる', r.rc === -5 && logValue(r.log, 'fail') === '1', brief(r));

    // 6. データのフレームのバージョンを書き換える
    n = stored();
    r = await run(x => { if (x.dir === 'toHost' && isData(x.f) && x.f.index === 2) { const b = Buffer.from(x.f.body); b[0] = 2; return b; } return null; }, 'put A-6');
    check('バージョンの違うデータのフレームを、ホストは受け入れない', r.rc !== 0 && stored() === n, brief(r));

    // 7. 機器の一時鍵を位数の小さい点に替える(ホストの X25519 の結果が全て 0)
    r = await run(x => { if (x.dir === 'toHost' && x.f.type === TYPES.hs1) { const b = Buffer.from(x.f.body); LOW_ORDER.copy(b, 2); return b; } return null; }, 'put A-7');
    const hostFail7 = r.st.fromHost.find(f => f.type === TYPES.fail);
    check('一時鍵が位数の小さい点なら、ホストはハンドシェイクを失敗にする', r.rc === -5 && hostFail7 && hostFail7.body[2] === 2, brief(r));

    // 8. ホストの一時鍵を位数の小さい点に替える(機器の X25519 の結果が全て 0)
    r = await run(x => { if (x.dir === 'toDev' && x.f.type === TYPES.hs2) { const b = Buffer.from(x.f.body); LOW_ORDER.copy(b, 2); return b; } return null; }, 'put A-8');
    check('一時鍵が位数の小さい点なら、機器はハンドシェイクを失敗にする', r.rc !== 0 && !r.st.fromDev.some(f => f.type === TYPES.hs3), brief(r));

    // 8b. ee が全て 0 になるように最後まで計算したホスト。比べるため、正しい一時鍵で同じことをしたホストも
    const failCode = b => (b && b[0] === VERSION && b[1] === TYPES.fail ? b[2] : null);
    const show = b => (b ? (b[0] === VERSION ? b.toString('hex') : b.toString()) : 'なし');
    for (const low of [false, true]) {
      const zh = await zeroHost(low);
      r = await run(null, `put A-8b${low ? '' : '0'}`, { upstream: zh.port });
      const devFail = zh.reply();
      zh.close();
      if (low) check('ee が全て 0 のハンドシェイクを、機器は X25519 の結果で見つけて断る(理由 2)', r.rc === -4 && failCode(devFail) === 2, `${brief(r)} 機器の返事 ${show(devFail)}`);
      else check('(比べるため)正しい一時鍵で同じように作ったホストは、機器が知らないホストとして断る(理由 3)', r.rc === -6 && failCode(devFail) === 3, `${brief(r)} 機器の返事 ${show(devFail)}`);
    }

    // 8c. se が全て 0 になるように最後まで計算した機器。比べるため、正しい静的な鍵で同じことをした機器も
    let hostFail = await zeroDevice(A.port, false);
    check('(比べるため)正しい静的な鍵で同じように作った機器は、ホストがペアリングしていない機器として断る(理由 3)', failCode(hostFail) === 3, show(hostFail));
    hostFail = await zeroDevice(A.port, true);
    check('se が全て 0 のハンドシェイクを、ホストは X25519 の結果で見つけて断る(理由 2)', failCode(hostFail) === 2, show(hostFail));

    // 9. 長さが 2 未満のフレーム
    r = await run({ after(x) { if (x.dir === 'toHost' && x.f.type === TYPES.hs1) x.raw('toHost', Buffer.from([0, 1, 1])); } }, 'put A-9');
    check('長さが 2 未満のフレームを受けたホストは、接続を閉じる', r.rc !== 0 && r.st.closedBy === 'host', brief(r));
    r = await run({ after(x) { if (x.dir === 'toDev' && x.f.type === TYPES.hs2) x.raw('toDev', Buffer.from([0, 0])); } }, 'put A-9b');
    check('長さが 2 未満のフレームを受けた機器は、セッションを終える', r.rc !== 0, brief(r));

    // 10. 機器の上限を超える長さ
    r = await run({ after(x) { if (x.dir === 'toHost' && x.f.type === TYPES.hs1) x.raw('toDev', Buffer.concat([Buffer.from([0x10, 0x00]), crypto.randomBytes(0x1000)])); } }, 'put A-10b');
    check('上限を超える長さのフレームを受けた機器は、セッションを終える', r.rc !== 0, brief(r));

    // 11. 受け入れの後に、偽の失敗のフレームを機器へ
    r = await run({ after(x) { if (x.dir === 'toDev' && isData(x.f) && x.st.fromHost.filter(isData).length === 1) x.inject('toDev', failFrame(3)); } }, 'put A-11');
    check('TCP では、失敗のフレームで機器はセッションを終える(鍵とペアリングは変えない)', r.rc === -5, brief(r));

    // 12. 別の鍵のホスト(なりすまし)へつなぐ
    r = await run(null, 'put A-12', { upstream: B.port });
    check('覚えていない鍵のホストとは、機器は話さない', r.rc === -6, brief(r));

    // 13. 別の鍵の機器(なりすまし)がジョブを取りに来る
    if (!isBoard) {
      const id13 = seed('SECRET-13', 'Q-13');
      proxy.set(null, A.port);
      const pend0 = Object.keys(A.route('GET', 'peers')({}).pending).length;
      r = await simRun(proxy.port, 'get Q-13', { state: `${STATE}-other`, pair: true });
      const pend = Object.keys(A.route('GET', 'peers')({}).pending);
      const leaked = proxy.last && Buffer.concat(proxy.last.wire).toString('latin1').includes('SECRET-13');
      check('ペアリングしていない機器は、ホストに断られ、ジョブを受け取れない', r.rc === -5 && logValue(r.log, 'fail') === '3' && A.hub.store.get(id13).status !== 'sent' && !leaked && pend.length === pend0 + 1, `${brief(r)} 待ち ${pend0} → ${pend.length}`);
    }

    // 14. セッションの途中で接続を切る
    r = await run(x => (x.dir === 'toDev' && isData(x.f) && x.st.fromHost.filter(isData).length === 2 ? 'cut' : null), 'put A-14');
    check('途中で切られた機器は、セッションを終える', r.rc !== 0, brief(r));

    // 最後: 何もしなければ通る
    n = stored();
    r = await run(null, 'put A-15');
    check('攻撃の後も、割り込まなければ PUT が通る', r.rc === 0 && r.status === 0 && stored() === n + 1, brief(r));
    if (isBoard) {
      const lan = await h8Command('lan');
      console.log(`    (基板の LAN の数: ${lan.split(/\r?\n/).find(l => /up=/.test(l))})`);
    }
  } finally {
    proxy.close();
    await A.hub.stop(); await B.hub.stop();
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  }
  console.log(failed ? `失敗 ${failed} 件` : 'すべて通った');
  process.exit(failed ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(2); });
