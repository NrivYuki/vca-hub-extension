'use strict';
// 実際の機器の側の実装(C の模擬機器、または H8 の基板)と vca-hub をつないで、規格の流れをひととおり確かめる。
//   node tools/verify-device.js sim         WSL で動かす C の模擬機器(先に参照実装のフォルダの WSL で make -C c sim_device)
//   node tools/verify-device.js h8 [COM11]  H8 の基板(ファームウェアを書いてあること。DIP スイッチは ON・OFF・ON・ON)
//   node tools/verify-device.js h8lan [COM11]  H8 の基板を LAN で(基板の ip コマンドでこの PC のアドレスとポート 33520 を設定しておく)
// 機器の側は参照実装(optical-lab-device-protocol-reference)の C の模擬機器・H8 の道具・見本のジョブを使う(場所は oldp/reference.js)。
// vca-hub は一時フォルダのデータで、このプロセスの中で動かす。

const { spawn } = require('node:child_process');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');

const EXT_ROOT = path.join(__dirname, '..');
const { root: ROOT } = require('../oldp/reference.js');
// ホストの vca-hub は、隣のフォルダ(../vca-hub)か、環境変数 OLDP_VCA_HUB の場所のものを使う
const HUB = process.env.OLDP_VCA_HUB || path.join(EXT_ROOT, '..', 'vca-hub');
if (!fs.existsSync(path.join(HUB, 'src', 'app.js'))) { console.error(`vca-hub が見つかりません(${HUB})。隣のフォルダに置くか、OLDP_VCA_HUB で場所を指定してください`); process.exit(2); }
const { loadConfig, merge } = require(path.join(HUB, 'src', 'config.js'));
const { createHub } = require(path.join(HUB, 'src', 'app.js'));
const target = process.argv[2] || 'sim';
const comPort = process.argv[3] || 'COM11';
const overLan = target === 'h8lan';
const isBoard = target === 'h8' || overLan;
const sample = fs.readFileSync(path.join(ROOT, 'samples', 'frame-both.vca'), 'latin1').replace('REQ=FIL', 'ANS=TRC');

let failed = 0;
function check(name, ok, detail) {
  console.log(`${ok ? 'OK' : 'NG'}  ${name}${detail !== undefined ? `  [${detail}]` : ''}`);
  if (!ok) failed++;
}

function logValue(log, key) {
  const m = new RegExp(`(?:^|\\s)${key}=(\\S*)`).exec(log);
  return m ? m[1] : undefined;
}

function collect(child) {
  let out = '';
  child.stdout.on('data', d => { out += d.toString('utf8'); });
  child.stderr.on('data', d => { out += d.toString('utf8'); });
  return () => out;
}

// ---- 機器の操作 ----
const SIM_STATE = `/tmp/oldp-verify-${process.pid}`;
const SIM_PORT = 35100 + (process.pid % 400);

function simRun(hubPort, cmd, { pair = false, trace = 0, uart = true } = {}) {
  return new Promise((resolve, reject) => {
    const args = ['-e', 'c/sim_device', cmd, '--listen', String(SIM_PORT), '--state', SIM_STATE, '--file', 'samples/frame-right.vca'];
    if (pair) args.push('--pair');
    if (uart) args.push('--uart');
    if (trace) args.push('--trace', String(trace));
    const child = spawn('wsl', args, { cwd: ROOT });
    const text = collect(child);
    // 止まったままにしない(wait 180 が最も長い)
    const limit = setTimeout(() => child.kill(), 240000);
    let tries = 0;
    // WSL の待ち受けが Windows の側から見えるようになるまで、つなぎ直す
    const bridge = () => {
      const a = net.connect(SIM_PORT, '127.0.0.1');
      a.once('error', () => {
        if (++tries > 60) { child.kill(); return; }
        setTimeout(bridge, 500);
      });
      a.once('connect', () => {
        const b = net.connect(hubPort, '127.0.0.1');
        a.pipe(b); b.pipe(a);
        a.removeAllListeners('error');
        for (const s of [a, b]) s.on('error', () => { a.destroy(); b.destroy(); });
      });
    };
    const timer = setInterval(() => {
      if (!text().includes('LISTENING')) return;
      clearInterval(timer);
      bridge();
    }, 100);
    child.on('error', reject);
    child.on('close', () => {
      clearInterval(timer);
      clearTimeout(limit);
      const m = /OLDP-END (-?\d+) (-?\d+)\r?\n(.*)/.exec(text());
      if (!m) return reject(new Error(`模擬機器の結果がありません: ${text()}`));
      resolve({ rc: Number(m[1]), status: Number(m[2]), log: m[3] });
    });
  });
}

function pwsh(args) {
  return new Promise((resolve, reject) => {
    const child = spawn('pwsh', ['-NoProfile', '-File', ...args], { cwd: ROOT, env: { ...process.env, PYTHONIOENCODING: 'utf8' } });
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

let h8Trace = 360;
async function h8Run(hubPort, cmd, { pair = false, trace = 0 } = {}) {
  if ((trace || 360) !== h8Trace) { h8Trace = trace || 360; await h8Command(`trace ${h8Trace}`); }
  const a = ['tools/h8-session.ps1', '-Port', comPort, '-Command', cmd, ...(overLan ? ['-Lan'] : ['-Hub', `127.0.0.1:${hubPort}`])];
  if (pair) a.push('-Pair');
  const r = await pwsh(a);
  const end = /(?:戻り値|\?\?\?)?\s*(-?\d+)[^\d-]+STATUS\s+(-?\d+)/.exec(r.out);
  const log = r.out.trim().split(/\r?\n/).filter(l => / rc=/.test(l)).pop() || '';
  if (!log || !end) throw new Error(`基板の結果がありません: ${r.out}`);
  return { rc: Number(logValue(log, 'rc')), status: Number(logValue(log, 'status')), log };
}

const wait = ms => new Promise(r => setTimeout(r, ms));

async function main() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'oldp-verify-'));
  const cfg = merge(loadConfig(path.join(dir, 'none.json')), {
    dataDir: path.join(dir, 'data'), web: { enabled: false }, remote: { enabled: false }, connectDelay: 0,
    extensionsDir: EXT_ROOT, extensions: { 'oldp': true },
    // 基板と PC を直結した LAN はリンクローカルのアドレスになる
    ...(overLan ? { allow: ['127.0.0.1/32', '169.254.0.0/16'] } : {}),
    listeners: [
      { name: 'uart', port: 0, protocol: 'oldp', settings: { transport: 'uart' } },
      { name: 'tcp', port: overLan ? 33520 : 0, protocol: 'oldp' },
    ],
  });
  const hub = createHub(cfg);
  const ports = await hub.start();
  const ext = hub.ext.get('oldp');
  const route = (m, p) => ext.routes.find(r => r.method === m && r.path === p).handler;
  const hostFp = route('GET', 'peers')({}).host;
  const uartPort = ports.listeners.uart;
  const run = (cmd, o) => { const t0 = Date.now(); return (isBoard ? h8Run(uartPort, cmd, o) : simRun(uartPort, cmd, o)).then(r => { r.sec = ((Date.now() - t0) / 1000).toFixed(1); return r; }); };
  const seed = (job, name, body = sample) => { const e = hub.store.saveReceived({ body, type: 'TRC', job, peer: 'verify', crcOk: null }); hub.store.queue(e.id, name); return e.id; };
  const statusOf = id => hub.store.get(id).status;
  const describe = id => (hub.ext.describe(hub.store.get(id)).find(d => d.name === 'oldp') || { lines: [] }).lines.join(' / ');

  console.log(`対象: ${target}  ホスト ${hostFp}  UART の待ち受け ${uartPort}`);
  try {
    if (isBoard) check('初期化: 覚えたホストを消す', /ok/.test(await h8Command('unpair')));

    let r = await run('put T-1');
    check('ペアリングの受付でなければ、機器は知らないホストと話さない', r.rc === -6, r.log);

    r = await run('put T-1', { pair: true });
    check('受付中の機器はホストを覚え、ホストはペアリング待ちで断る', r.rc === -5 && logValue(r.log, 'fail') === '3', `${r.sec} 秒 ${r.log}`);
    check('機器がホストのフィンガープリントを知った', logValue(r.log, 'host') === hostFp);
    const pending = Object.keys(route('GET', 'peers')({}).pending);
    check('ペアリング待ちに載る', pending.length === 1, pending[0]);
    route('POST', 'trust')({ body: { fingerprint: pending[0] } });
    const devFp = pending[0];

    r = await run('put T-1');
    check('PUT が保存される', r.rc === 0 && r.status === 0 && hub.store.list().length === 1, `${r.sec} 秒 ${r.log}`);
    const stored = hub.store.list()[0];
    check('保存した中身は VCA として読める', stored.job === 'T-1' && stored.check.blockers.length === 0, stored.check.blockers.join());

    r = await run('put T-1');
    check('同じ PUT は 2 度目を保存しない', r.rc === 0 && r.status === 0 && hub.store.list().length === 1, `${r.sec} 秒`);

    r = await run('get E-1');
    check('名前の無いジョブの GET は STATUS=1', r.rc === 0 && r.status === 1, r.log);

    let id = seed('D-1', 'E-1');
    r = await run('get E-1');
    check('GET で受け、RESULT で送信済みになる', r.rc === 0 && r.status === 0 && statusOf(id) === 'sent', `${r.sec} 秒 ${r.log}`);
    check('両眼の玉型の点の数が合う', logValue(r.log, 'traces') === '2' && logValue(r.log, 'bad') === '0');
    check('ホストは機器が申告した項目だけを送り、捨てられた項目が無い', /STATUS=0/.test(describe(id)) && !/捨てた/.test(describe(id)), describe(id));

    id = seed('D-2', 'E-2');
    r = await run('ops T-2 E-2');
    check('1 つのセッションで TIME・PING・PUT・GET・RESULT・INFO', r.rc === 0 && ['r_time', 'r_ping', 'r_put', 'r_get', 'r_result', 'r_info'].every(k => logValue(r.log, k) === '0'), `${r.sec} 秒 ${r.log}`);
    check('TIME はホストの協定世界時', /^20\d{12}$/.test(logValue(r.log, 'time') || '') && logValue(r.log, 'time').startsWith(new Date().toISOString().slice(0, 10).replace(/-/g, '')), logValue(r.log, 'time'));
    check('ops の GET が送信済みになる', statusOf(id) === 'sent');
    check('ops の PUT が保存される', hub.store.list().some(e => e.job === 'T-2'));

    id = seed('D-3', 'E-3');
    r = await run('wait 60');
    check('つないだときに、送信待ちを AVAIL で知らせる', r.rc === 0 && logValue(r.log, 'avail') === 'E-3' && statusOf(id) === 'sent', `${r.sec} 秒 ${r.log}`);

    // つないだまま待っている機器へ、PING と AVAIL を送る
    const live = run('wait 180');
    let con = [];
    for (let i = 0; i < 1200 && !con.length; i++) { await wait(100); con = route('GET', 'connected')({}); }
    check('つないだままの機器が一覧に載る', con.length === 1 && con[0].fingerprint === devFp);
    const ping = await route('POST', 'ping')({ body: { fingerprint: devFp } }).catch(e => ({ error: e.message }));
    check('ホストからの PING に答える', ping.ok === true, JSON.stringify(ping));
    id = seed('D-4', 'E-4');
    r = await live;
    check('送信待ちにすると AVAIL が届き、機器が取りに来る', r.rc === 0 && logValue(r.log, 'avail') === 'E-4' && statusOf(id) === 'sent' && logValue(r.log, 'pings') !== '0', `${r.sec} 秒 ${r.log}`);

    // 機器が受けられない値(桁が多い屈折率)
    id = seed('D-5', 'E-5', sample.replace(/\r\nTRCFMT/, '\r\nLIND=1.6001;1.6001\r\nTRCFMT'));
    r = await run('get E-5');
    check('受けられない値は RESULT の REJECTED で返り、送信済みにしない', r.rc === 0 && /LIND/.test(logValue(r.log, 'rejected') || '') && statusOf(id) === 'queued', `${r.log}`);
    check('受けられなかった項目をホストが記録する', /受けられない LIND/.test(describe(id)), describe(id));
    hub.store.unqueue(id);

    if (isBoard) {
      const banner = await h8Command('reset').catch(e => e.message);
      await wait(1500);
      const hosts = await h8Command('hosts');
      check('起動し直しても、覚えたホストはフラッシュに残る', hosts.includes(hostFp), `${hosts.split(/\r?\n/).pop()} ${banner.length}`);
    }
    r = await run('put T-9');
    check('起動し直したあと、ペアリングの受付なしでつながる', r.rc === 0 && r.status === 0, r.log);

    id = seed('D-6', 'E-6');
    r = await run('get E-6', { trace: 1440 });
    check('1440 点の玉型(両眼)を受ける', r.rc === 0 && r.status === 0 && logValue(r.log, 'traces') === '2' && logValue(r.log, 'bad') === '0' && statusOf(id) === 'sent', `${r.sec} 秒 ${r.log}`);

    route('POST', 'untrust')({ body: { fingerprint: devFp } });
    r = await run('put T-10', { trace: 360 });
    check('ホストでペアリングを外すと断られる', r.rc === -5 && logValue(r.log, 'fail') === '3', r.log);

    if (isBoard) {
      check('機器のペアリングを解除する', /ok/.test(await h8Command('unpair')));
      r = await run('put T-11');
      check('機器のペアリングを解除すると、ホストと話さない', r.rc === -6, r.log);

      // 標準の拡張 OLDPKEY(規格 15 章)
      r = await run('put T-30', { pair: true });
      check('鍵の交換の準備: もう一度ペアリングする', r.rc === -5 && logValue(r.log, 'fail') === '3', r.log);
      route('POST', 'trust')({ body: { fingerprint: devFp } });
      r = await run('rekey 1');
      check('OLDPKEY: 鍵の交換をホストが受け付ける', r.rc === 0 && r.status === 0, `${r.sec} 秒 ${r.log}`);
      const newFp = (await h8Command('id')).split(/\s+/).pop();
      check('OLDPKEY: 機器のフィンガープリントが新しい鍵に変わる', /^[0-9A-Z]{4}(-[0-9A-Z]{4}){3}$/.test(newFp) && newFp !== devFp, newFp);
      let trusted = route('GET', 'peers')({}).trusted;
      check('OLDPKEY: 新しい鍵でつながるまで、ホストは両方を信じる', !!trusted[devFp] && !!trusted[newFp], Object.keys(trusted).join(' '));
      r = await run('put T-31');
      check('OLDPKEY: 新しい鍵でつながる(ペアリングのやり直しなし)', r.rc === 0 && r.status === 0, r.log);
      trusted = route('GET', 'peers')({}).trusted;
      check('OLDPKEY: 新しい鍵でつながると、ホストは前の鍵を信じない', !trusted[devFp] && !!trusted[newFp], Object.keys(trusted).join(' '));
      await h8Command('reset').catch(() => {});
      await wait(1500);
      check('OLDPKEY: 起動し直しても新しい鍵のまま', (await h8Command('id')).includes(newFp));
      check('書き込んだときの鍵に戻す', /ok/.test(await h8Command('keyreset')) && (await h8Command('id')).includes(devFp));
      check('機器のペアリングを解除する(終わりの片付け)', /ok/.test(await h8Command('unpair')));
    } else {
      // TCP のトランスポートも通す
      route('POST', 'trust')({ body: { fingerprint: devFp } });
      id = seed('D-7', 'E-7');
      r = await simRun(ports.listeners.tcp, 'ops T-20 E-7', { uart: false });
      check('TCP のトランスポートでも TIME・PING・PUT・GET・RESULT・INFO が通る', r.rc === 0 && statusOf(id) === 'sent' && logValue(r.log, 'r_info') === '0', r.log);
    }
  } finally {
    await hub.stop();
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  }
  console.log(failed ? `失敗 ${failed} 件` : 'すべて通った');
  process.exit(failed ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(2); });
