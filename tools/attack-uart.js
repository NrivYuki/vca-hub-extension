'use strict';
// UART の線に割り込む相手を置いて、機器の側の実装(C の模擬機器、または H8 の基板)の動作を確かめる。
//   node tools/attack-uart.js sim
//   node tools/attack-uart.js h8 [COM11] [速度]
// 機器と vca-hub の UART の待ち受けの間に、この道具の中継を挟む。中継は線の上のバイトを全て見て、
// フレームの差し込み・書き換え・送り直し・捨てることができる(線に割り込む相手と同じことができる)。
// 電気の層の攻撃(雑音・電圧)は扱わない。

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
const { uartEncode, uartDecode, TYPES, VERSION } = require(path.join(ROOT, 'js', 'src', 'frame.js'));

const target = process.argv[2] || 'sim';
const comPort = process.argv[3] || 'COM11';
const baud = process.argv[4] || '9600';
const isBoard = target === 'h8';

let failed = 0;
function check(name, ok, detail) {
  console.log(`${ok ? 'OK' : 'NG'}  ${name}${detail !== undefined ? `  [${detail}]` : ''}`);
  if (!ok) failed++;
}
const logValue = (log, key) => { const m = new RegExp(`(?:^|\\s)${key}=(\\S*)`).exec(log); return m ? m[1] : undefined; };
const wait = ms => new Promise(r => setTimeout(r, ms));

// ---- 線に割り込む中継 ----
// 機器の側(h8-session.ps1 の中継、または模擬機器)から受けて、vca-hub の UART の待ち受けへつなぐ。
// attack は 1 つのセッションの間だけ使う手順で、各方向のフレームを見て、通す・書き換える・差し込むを決める。
function startProxy(hubPort) {
  let attack = null, ctx = {};
  // attack は関数(各フレームを通す前に呼ぶ。'drop' で捨て、Buffer を返せば書き換える)か、{ after }(通した後に呼ぶ)
  const before = x => (typeof attack === 'function' ? attack.call(ctx, x) : null);
  const after = x => { if (attack && typeof attack.after === 'function') attack.after.call(ctx, x); };
  const server = net.createServer(dev => {
    const host = net.connect(hubPort, '127.0.0.1');
    const st = { fromDev: [], fromHost: [], injected: new Set(), log: [] };
    const send = { toDev: b => dev.write(b), toHost: b => host.write(b) };
    // 差し込んだフレームへの ACK は、相手に届けない(相手の待っている番号と重なって、届いたと思わせないため)
    const inject = (dir, frame, lseq) => {
      const seq = lseq === undefined ? (0x80 | crypto.randomInt(0x80)) : lseq;
      st.injected.add(`${dir === 'toDev' ? 'dev' : 'host'}:${seq}`);
      send[dir](uartEncode(0, seq, frame));
      st.log.push(`${dir} に差し込み(${frame.length} バイト)`);
    };
    const raw = (dir, bytes) => { send[dir](bytes); st.log.push(`${dir} にバイト列(${bytes.length})`); };
    const pipe = (from, dir, list) => {
      let buf = [];
      from.on('data', chunk => {
        for (const b of chunk) {
          buf.push(b);
          if (b !== 0) continue;
          const bytes = Buffer.from(buf);
          buf = [];
          const u = bytes.length > 1 ? uartDecode(bytes.subarray(0, bytes.length - 1)) : null;
          // ACK: 差し込んだフレームへのものは捨てる
          if (u && u.kind === 1) {
            const key = `${dir === 'toHost' ? 'dev' : 'host'}:${u.lseq}`;
            if (st.injected.has(key)) { st.injected.delete(key); continue; }
            send[dir](bytes);
            continue;
          }
          if (!u) { send[dir](bytes); continue; }
          const f = { lseq: u.lseq, body: u.body, type: u.body[1], index: list.length };
          list.push(f);
          const act = before({ dir, f, st, inject, raw });
          if (act === 'drop') { st.log.push(`${dir} のフレームを捨てた(種類 ${f.type})`); continue; }
          if (Buffer.isBuffer(act)) { send[dir](uartEncode(0, f.lseq, act)); st.log.push(`${dir} のフレームを書き換えた`); continue; }
          send[dir](bytes);
          after({ dir, f, st, inject, raw });
        }
      });
    };
    pipe(dev, 'toHost', st.fromDev);
    pipe(host, 'toDev', st.fromHost);
    const end = () => { dev.destroy(); host.destroy(); };
    dev.on('error', end); host.on('error', end); dev.on('close', end); host.on('close', end);
    server.last = st;
  });
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve({
    port: server.address().port,
    set(a) { attack = a; ctx = {}; server.last = null; },
    get last() { return server.last; },
    close: () => server.close(),
  })));
}

// ---- 機器の操作(verify-device.js と同じ) ----
function collect(child) { let out = ''; child.stdout.on('data', d => { out += d.toString('utf8'); }); child.stderr.on('data', d => { out += d.toString('utf8'); }); return () => out; }
const SIM_STATE = `/tmp/oldp-attack-${process.pid}`;
const SIM_PORT = 35500 + (process.pid % 400);
function simRun(port, cmd, { pair = false } = {}) {
  return new Promise((resolve, reject) => {
    const args = ['-e', 'c/sim_device', cmd, '--listen', String(SIM_PORT), '--state', SIM_STATE, '--file', 'samples/frame-right.vca', '--uart'];
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
const serialArgs = ['-Port', comPort, '-BaudRate', baud];
async function h8Command(cmd) {
  const r = await pwsh(['tools/h8-session.ps1', ...serialArgs, '-Command', cmd]);
  if (r.code) throw new Error(`基板が応えません(${cmd}): ${r.out}`);
  return r.out.trim();
}
async function h8Run(port, cmd, { pair = false } = {}) {
  const a = ['tools/h8-session.ps1', ...serialArgs, '-Command', cmd, '-Hub', `127.0.0.1:${port}`];
  if (pair) a.push('-Pair');
  const r = await pwsh(a);
  const log = r.out.trim().split(/\r?\n/).filter(l => / rc=/.test(l)).pop() || '';
  if (!log) throw new Error(`基板の結果がありません: ${r.out}`);
  return { rc: Number(logValue(log, 'rc')), status: Number(logValue(log, 'status')), log };
}

// ---- 攻撃に使うフレーム ----
const failFrame = code => Buffer.from([VERSION, TYPES.fail, code]);
const isData = f => f.type === TYPES.data;
const flipped = body => { const b = Buffer.from(body); b[b.length - 20] ^= 0x01; return b; };   // 暗号文(認証タグの手前)の 1 ビット
// 位数の小さい点(X25519 の結果が全て 0 になる)
const LOW_ORDER = Buffer.from('e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800', 'hex');

async function main() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'oldp-attack-'));
  const cfg = merge(loadConfig(path.join(dir, 'none.json')), {
    dataDir: path.join(dir, 'data'), web: { enabled: false }, remote: { enabled: false }, connectDelay: 0,
    extensionsDir: EXT_ROOT, extensions: { 'oldp': true },
    listeners: [{ name: 'uart', port: 0, protocol: 'oldp', settings: { transport: 'uart' } }],
  });
  const hub = createHub(cfg);
  const ports = await hub.start();
  const ext = hub.ext.get('oldp');
  const route = (m, p) => ext.routes.find(r => r.method === m && r.path === p).handler;
  const proxy = await startProxy(ports.listeners.uart);
  const runRaw = (cmd, o) => (isBoard ? h8Run(proxy.port, cmd, o) : simRun(proxy.port, cmd, o));
  const run = async (attack, cmd, o) => { proxy.set(attack); const t0 = Date.now(); const r = await runRaw(cmd, o); r.sec = ((Date.now() - t0) / 1000).toFixed(1); r.st = proxy.last; return r; };
  const stored = () => hub.store.list().length;
  const seed = (job, name) => {
    const body = fs.readFileSync(path.join(ROOT, 'samples', 'frame-both.vca'), 'latin1').replace('REQ=FIL', 'ANS=TRC');
    const e = hub.store.saveReceived({ body, type: 'TRC', job, peer: 'attack', crcOk: null });
    hub.store.queue(e.id, name);
    return e.id;
  };
  const brief = r => `${r.sec} 秒 rc=${r.rc} status=${r.status}${r.st ? ' ' + r.st.log.join('、') : ''}`;
  console.log(`対象: ${target}${isBoard ? ` ${comPort} ${baud} bps` : ''}`);

  try {
    // 準備: ペアリング
    if (isBoard) await h8Command('unpair');
    await run(null, 'put P-1', { pair: true });
    const pending = Object.keys(route('GET', 'peers')({}).pending);
    route('POST', 'trust')({ body: { fingerprint: pending[0] } });

    let r = await run(null, 'put A-0');
    check('割り込まないとき、PUT が通る', r.rc === 0 && r.status === 0, brief(r));
    const oldHostData = r.st.fromHost.filter(isData).map(f => f.body);

    // 1. ハンドシェイクの後に、偽の FAIL を機器へ差し込む
    let n = stored();
    r = await run({ after({ dir, f, inject }) { if (dir === 'toHost' && isData(f) && f.index === 2) inject('toDev', failFrame(3)); } }, 'put A-1');
    check('ハンドシェイクの後の偽の FAIL を、機器は捨ててセッションを続ける', r.rc === 0 && r.status === 0 && stored() === n + 1, brief(r));

    // ホストから機器への DATA のうち、n 番目(1 番目は受け入れの通知、2 番目は PUT の応答)
    const nthHostData = (x, k) => x.dir === 'toDev' && isData(x.f) && x.st.fromHost.filter(isData).length === k;

    // 2. PUT の応答を 1 ビット書き換えたものを、本物の前に差し込む
    n = stored();
    r = await run(x => { if (nthHostData(x, 2)) x.inject('toDev', flipped(x.f.body)); return null; }, 'put A-2');
    check('書き換えた応答を差し込んでも、機器は捨てて本物を受ける', r.rc === 0 && r.status === 0 && stored() === n + 1, brief(r));

    // 3. PUT の応答を、書き換えたものに置き換える(本物は届かない)
    r = await run(x => (nthHostData(x, 2) ? flipped(x.f.body) : null), 'put A-3');
    check('書き換えた応答だけが届くと、機器は受け入れず、応答の時間切れで終える', r.rc === -2, brief(r));

    // 3b. 受け入れの通知を書き換える。機器はまだセッションを使える状態でないので、捨てて続ける決まり(規格 4 章)の外で、セッションを終える
    r = await run(x => (nthHostData(x, 1) ? flipped(x.f.body) : null), 'put A-3b');
    check('受け入れの通知を書き換えると、機器はセッションを終える(使える状態になる前)', r.rc === -4, brief(r));

    // 4. 同じセッションの前の応答を送り直す(TIME の応答を、後の要求の応答の前に)
    let id = seed('D-4', 'E-4');
    r = await run(function (x) {
      if (x.dir !== 'toDev' || !isData(x.f)) return null;
      const datas = x.st.fromHost.filter(isData);
      if (datas.length === 2) x.inject('toDev', datas[0].body);
      return null;
    }, 'ops T-4 E-4');
    check('同じセッションの前の応答を送り直しても、機器は捨てる', r.rc === 0 && ['r_time', 'r_ping', 'r_put', 'r_get', 'r_result', 'r_info'].every(k => logValue(r.log, k) === '0') && hub.store.get(id).status === 'sent', brief(r));

    // 5. 前のセッションのホストの応答を送り直す
    n = stored();
    r = await run({ after({ dir, f, inject }) { if (dir === 'toHost' && isData(f) && f.index === 2) for (const b of oldHostData) inject('toDev', b); } }, 'put A-5');
    check('前のセッションの応答を送り直しても、機器は捨てる', r.rc === 0 && r.status === 0 && stored() === n + 1, brief(r));

    // 6. 壊れたバイト列を差し込む
    n = stored();
    r = await run({ after({ dir, f, raw }) {
      if (dir !== 'toHost' || !isData(f) || f.index !== 2) return;
      raw('toDev', Buffer.concat([crypto.randomBytes(200).map(b => b || 1), Buffer.from([0])]));            // COBS として壊れている
      raw('toDev', Buffer.alloc(16));                                                                       // 区切りだけ
      raw('toDev', Buffer.concat([Buffer.alloc(1500, 0x41), Buffer.from([0])]));                            // フレームの上限より長い
      const bad = uartEncode(0, 0x55, failFrame(3)); bad[3] ^= 0xff; raw('toDev', bad);                     // CRC が合わない
      raw('toDev', uartEncode(1, 0x7e));                                                                     // 待っていない ACK
    } }, 'put A-6');
    check('壊れたバイト列や長すぎるものを差し込んでも、機器はセッションを続ける', r.rc === 0 && r.status === 0 && stored() === n + 1, brief(r));

    // 7. ハンドシェイクの途中に、偽の FAIL を機器へ差し込む(暗号で確かめられる前なので、機器は終える。規格 6 章の限界)
    r = await run({ after({ dir, f, inject }) { if (dir === 'toHost' && f.type === TYPES.hs1) inject('toDev', failFrame(2)); } }, 'put A-7');
    check('ハンドシェイクの途中の偽の FAIL では、機器はセッションを終える(何も受け入れない)', r.rc === -5, brief(r));

    // 8. ホストが受け入れの通知を送った後に、偽の FAIL をホストへ差し込む
    n = stored();
    r = await run({ after(x) { if (nthHostData(x, 1)) x.inject('toHost', failFrame(3)); } }, 'put A-8');
    check('受け入れの後の偽の FAIL を、ホストは捨ててセッションを続ける', r.rc === 0 && r.status === 0 && stored() === n + 1, brief(r));

    // 8b. 3 つ目のハンドシェイクのメッセージの直後(ホストが受け入れる前)に、偽の FAIL をホストへ差し込む
    r = await run({ after({ dir, f, inject }) { if (dir === 'toHost' && f.type === TYPES.hs3) inject('toHost', failFrame(3)); } }, 'put A-8b');
    check('ホストが受け入れる前の偽の FAIL では、セッションが終わる(何も受け入れない)', r.rc !== 0, brief(r));

    // 9. 機器の要求を書き換えたものを、本物の前にホストへ差し込む
    n = stored();
    r = await run(function (x) { if (x.dir === 'toHost' && isData(x.f) && !this.done) { this.done = true; x.inject('toHost', flipped(x.f.body)); } return null; }, 'put A-9');
    check('書き換えた要求を差し込んでも、ホストは捨てて本物を受ける', r.rc === 0 && r.status === 0 && stored() === n + 1, brief(r));

    // 9b. セッションが使える間に、一時鍵が位数の小さい点のハンドシェイクの 1 つ目をホストへ差し込む
    n = stored();
    r = await run({ after(x) { if (nthHostData(x, 1)) x.inject('toHost', Buffer.concat([Buffer.from([VERSION, TYPES.hs1]), LOW_ORDER])); } }, 'put A-9b');
    check('位数の小さい点の一時鍵で新しいハンドシェイクを差し込んでも、ホストは前のセッションを続ける', r.rc === 0 && r.status === 0 && stored() === n + 1, brief(r));

    // 9c. セッションが使える間に、新しいハンドシェイクの 1 つ目(正しい形)をホストへ差し込む
    n = stored();
    r = await run({ after(x) { if (nthHostData(x, 1)) x.inject('toHost', Buffer.concat([Buffer.from([VERSION, TYPES.hs1]), crypto.randomBytes(32)])); } }, 'put A-9c');
    check('新しいハンドシェイクの 1 つ目を差し込んでも、ホストは前のセッションを続ける', r.rc === 0 && r.status === 0 && stored() === n + 1, brief(r));

    // 10. 機器のハンドシェイクのフレームを捨て続ける
    r = await run(({ dir, f }) => (dir === 'toHost' && f.type === TYPES.hs1 ? 'drop' : null), 'put A-10');
    check('ハンドシェイクのフレームが届かなければ、機器は再送したあと終える', r.rc === -7, brief(r));

    // 最後: 何もしなければ通る(機器が止まったままになっていない)
    r = await run(null, 'put A-11');
    check('攻撃の後も、割り込まなければ PUT が通る', r.rc === 0 && r.status === 0, brief(r));
  } finally {
    proxy.close();
    await hub.stop();
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  }
  console.log(failed ? `失敗 ${failed} 件` : 'すべて通った');
  process.exit(failed ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(2); });
