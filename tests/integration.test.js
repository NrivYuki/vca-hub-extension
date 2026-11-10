'use strict';
// 疎通の確かめ: DCS の機器とこの規格の機器を、vca-hub(と、この拡張)を通してつなぐ。
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const REF = require('../oldp/reference.js');
const P = REF.P;
// 写した拡張(下の加工条件のテスト)からも、同じ参照実装を読めるようにする
process.env.OLDP_REFERENCE = REF.root;

// vca-hub の拡張のテストなので、vca-hub(隣のフォルダか、環境変数 OLDP_VCA_HUB の場所)が無ければ飛ばす
const HUB = process.env.OLDP_VCA_HUB || path.join(__dirname, '..', '..', 'vca-hub');
if (!fs.existsSync(path.join(HUB, 'src', 'app.js'))) {
  test(`vca-hub が無いので飛ばす(${HUB})`, { skip: true }, () => {});
  return;
}
const { loadConfig, merge } = require(path.join(HUB, 'src', 'config.js'));
const { createHub } = require(path.join(HUB, 'src', 'app.js'));
const T = require(path.join(HUB, 'src', 'lib', 'vca-tcp.js'));
const VCA = require(path.join(HUB, 'src', 'lib', 'vca-parser.js'));

const FAST = { ack: 1, packet: 2, char: 1 };
const sample = fs.readFileSync(path.join(REF.root, 'samples', 'frame-both.vca'), 'latin1');
const sampleDbl = (/^DBL=([^\r\n]*)/m.exec(sample) || [])[1];   // 見本の DBL(受け渡しで値が変わらないことを確かめる)
const sampleRecords = sample.split(/\r\n/).filter(l => l && !/^(REQ|JOB)=/.test(l)).map(l => { const i = l.indexOf('='); return [l.slice(0, i), l.slice(i + 1)]; });

const edgerCaps = [['VER', '1.0'], ['DEV', 'EDG'], ['VEN', 'SIM'], ['MODEL', 'EDGER'], ['SN', 'E1'], ['MAXFRAME', '512'],
  ['LABELS', 'JOB', 'DO', 'DBL', 'HBOX', 'VBOX', 'TRCFMT', 'R', 'ETYP', 'BEVP', 'BEVM', 'BEVC'], ['TRACE', '360', 'E']];
const tracerCaps = [['VER', '1.0'], ['DEV', 'TRC'], ['VEN', 'SIM'], ['MODEL', 'TRACER'], ['SN', 'T1'], ['MAXFRAME', '1024']];

async function makeHub(over = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'oldp-hub-'));
  const cfg = merge(loadConfig(path.join(dir, 'none.json')), {
    dataDir: path.join(dir, 'data'), web: { enabled: false }, remote: { enabled: true, port: 0 }, timeouts: FAST, connectDelay: 0,
    extensionsDir: path.join(__dirname, '..'), extensions: { 'oldp': true },
    listeners: [{ name: '新しい規格', port: 0, protocol: 'oldp' }], ...over,
  });
  const hub = createHub(cfg);
  const ports = await hub.start();
  const ext = hub.ext.get('oldp');
  const route = (m, p) => ext.routes.find(r => r.method === m && r.path === p).handler;
  return { hub, ports, port: ports.listeners['新しい規格'], route, async done() { await hub.stop(); await new Promise(r => setTimeout(r, 50)); fs.rmSync(dir, { recursive: true, force: true }); } };
}

/** 新しい規格の機器としてつなぐ。最初はペアリング待ちで断られるので、管理画面の「信じる」を行ってからつなぎ直す */
async function pairAndConnect(h, keys, caps) {
  const hostFp = h.route('GET', 'peers')({}).host;
  const opts = { keys, caps, trust: peer => peer.fingerprint === hostFp };
  await assert.rejects(P.connect('127.0.0.1', h.port, opts), e => e.code === 'refused-by-peer' && e.failCode === 3);
  const fp = P.noise.fingerprint(keys.publicKey);
  assert.ok(h.route('GET', 'peers')({}).pending[fp], 'ペアリング待ちに載る');
  h.route('POST', 'trust')({ body: { fingerprint: fp } });
  return P.connect('127.0.0.1', h.port, opts);
}

test('ホストの秘密鍵: 暗号化して置き、起動し直しても同じ鍵。暗号化していない形は暗号化して書き直す', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'oldp-key-'));
  const data = path.join(dir, 'data');
  const keyFile = path.join(data, 'ext', 'oldp', 'host-key.json');
  const host = async () => { const h = await makeHub({ dataDir: data }); const fp = h.route('GET', 'peers')({}).host; await h.done(); return fp; };
  try {
    const fp1 = await host();
    const saved = JSON.parse(fs.readFileSync(keyFile, 'utf8'));
    if (process.platform === 'win32') {
      assert.equal(saved.protection, 'dpapi-user');
      assert.equal(saved.privateKey, undefined, '秘密鍵をそのまま書かない');
    }
    assert.equal(await host(), fp1, '起動し直しても同じ鍵');

    const known = P.noise.keyPair();
    fs.writeFileSync(keyFile, JSON.stringify({ privateKey: known.privateKey.toString('hex') }));
    assert.equal(await host(), P.noise.fingerprint(known.publicKey), '暗号化していない形の鍵も読める');
    if (process.platform === 'win32') {
      const again = JSON.parse(fs.readFileSync(keyFile, 'utf8'));
      assert.equal(again.protection, 'dpapi-user', '読んだら暗号化して書き直す');
      assert.ok(!fs.readFileSync(keyFile, 'utf8').includes(known.privateKey.toString('hex')));
    }
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('OLDPKEY: 鍵を交換すると、前の鍵は新しい鍵でつながるまで信じられ、つながったあとは断られる', async () => {
  const h = await makeHub();
  try {
    const oldKeys = P.noise.keyPair(), newKeys = P.noise.keyPair();
    const caps = [...tracerCaps, ['EXT', 'OLDPKEY']];
    const hostFp = h.route('GET', 'peers')({}).host;
    let s = await pairAndConnect(h, oldKeys, caps);
    const key = hex => s.request(0x80, [['EXT', 'OLDPKEY'], ['KEY', hex]]);
    assert.equal((await key('abc')).status, 4, '形の正しくない鍵');
    assert.equal((await key(oldKeys.publicKey.toString('hex'))).status, 4, 'いまの鍵と同じ');
    assert.equal((await key(newKeys.publicKey.toString('hex'))).status, 0);
    s.close();
    const open = keys => P.connect('127.0.0.1', h.port, { keys, caps, trust: p => p.fingerprint === hostFp });
    s = await open(oldKeys);
    s.close();
    s = await open(newKeys);
    s.close();
    await assert.rejects(open(oldKeys), e => e.failCode === 3);
    assert.deepEqual(Object.keys(h.route('GET', 'peers')({}).trusted), [P.noise.fingerprint(newKeys.publicKey)]);
  } finally { await h.done(); }
});

test('OLDPKEY: 他の機器が使っている鍵には変えられない。宣言していない機器の操作は STATUS=3', async () => {
  const h = await makeHub();
  try {
    const a = P.noise.keyPair(), b = P.noise.keyPair();
    const caps = [...tracerCaps, ['EXT', 'OLDPKEY']];
    const sa = await pairAndConnect(h, a, caps);
    const sb = await pairAndConnect(h, b, tracerCaps);
    assert.equal((await sa.request(0x80, [['EXT', 'OLDPKEY'], ['KEY', b.publicKey.toString('hex')]])).status, 4);
    assert.equal((await sb.request(0x80, [['EXT', 'OLDPKEY'], ['KEY', a.publicKey.toString('hex')]])).status, 3);
    sa.close(); sb.close();
  } finally { await h.done(); }
});

test('拡張の受け口: 登録した名前空間を EXT= で知らせ、操作を渡す。REQUIRE= を満たさない機器は理由 5 で断る', async () => {
  const mod = require('../oldp/index.js');
  const seen = [];
  mod.vendor({ namespace: 'ACME', handle({ records, op, peer }) { seen.push([op, records, peer.caps.model]); return { records: [['STATUS', '0'], ['ACME:ECHO', records[0][1]]] }; } });
  const h = await makeHub({ listeners: [{ name: '新しい規格', port: 0, protocol: 'oldp', settings: { require: ['ACME'] } }] });
  try {
    const keys = P.noise.keyPair();
    const hostFp = h.route('GET', 'peers')({}).host;
    h.route('GET', 'peers')({});
    const open = caps => P.connect('127.0.0.1', h.port, { keys, caps, trust: p => p.fingerprint === hostFp });
    await assert.rejects(open(tracerCaps), e => e.failCode === 5);
    const caps = [...tracerCaps, ['EXT', 'ACME']];
    await assert.rejects(open(caps), e => e.failCode === 3);
    h.route('POST', 'trust')({ body: { fingerprint: P.noise.fingerprint(keys.publicKey) } });
    const s = await open(caps);
    assert.ok(s.peer.caps.ext.includes('ACME'));
    assert.ok(s.peer.caps.require.includes('ACME'));
    const r = await s.request(0x90, [['EXT', 'ACME'], ['ACME:IN', '7']]);
    assert.equal(r.status, 0);
    assert.deepEqual(r.records.find(x => x[0] === 'ACME:ECHO'), ['ACME:ECHO', '7']);
    assert.deepEqual(seen, [[0x90, [['ACME:IN', '7']], 'TRACER']]);
    s.close();
  } finally { await h.done(); }
});

test('DCS のトレーサー → vca-hub → この規格の加工機(ペアリング、GET、RESULT で送信済み、捨てた項目の記録)', async () => {
  const h = await makeHub();
  try {
    // DCS のトレーサーがアップロード(初期化しない REQ=TRC)
    const tracer = await T.connectDevice('127.0.0.1', h.ports.remote, { connectDelay: 0, timeouts: FAST, kind: 'upload' });
    const up = await tracer.request('TRC', { job: 'D-1', records: [['DEV', 'TRC'], ['VEN', 'DCS'], ['MODEL', 'T']], data: sampleRecords.concat([['FOO', '1']]) });
    tracer.socket.destroy();
    assert.equal(up.status, 0);
    const entry = h.hub.store.list()[0];
    h.hub.store.queue(entry.id, 'E-100');

    const s = await pairAndConnect(h, P.noise.keyPair(), edgerCaps);
    try {
      const r = await s.request('GET', [['JOB', 'E-100']]);
      assert.equal(r.opName, 'DATA');
      const recs = r.records;
      assert.equal(recs[0][1], 'E-100');
      const trc = recs.filter(x => x[0] === 'TRCFMT');
      assert.deepEqual(trc.map(x => x.slice(1, 5).join(';')), ['1;360;E;R', '1;360;E;L'], '機器が求めた点数・形式 1 で両眼');
      assert.deepEqual(P.records.checkTraces(recs), []);
      assert.ok(!recs.some(x => x.slice(1).includes('?')), '持っていない項目は送らない(? を使わない)');
      assert.deepEqual(recs.find(x => x[0] === 'DBL'), ['DBL', sampleDbl], '受け取った値のまま');
      const c = P.records.classify(recs, { accepts: new Set(edgerCaps.find(x => x[0] === 'LABELS').slice(1)) });
      assert.deepEqual(c.rejected, [], c.reasons.join());
      assert.equal(h.hub.store.get(entry.id).status, 'queued', 'RESULT を受けるまでは送信待ちのまま');
      await s.request('RESULT', [['JOB', 'E-100'], ['STATUS', '0'], ['IGNORED', 'XYZ']]);
      assert.equal(h.hub.store.get(entry.id).status, 'sent');
      assert.match(h.hub.ext.describe(entry).find(d => d.name === 'oldp').lines[0], /^\d\d\/\d\d \d\d:\d\d SIM EDGER STATUS=0 捨てた XYZ$/);
    } finally { s.close(); }
  } finally { await h.done(); }
});

test('この規格のトレーサー → vca-hub → DCS の加工機', async () => {
  const h = await makeHub();
  try {
    const s = await pairAndConnect(h, P.noise.keyPair(), tracerCaps);
    try {
      const r = await s.request('PUT', [['JOB', 'N-1'], ...sampleRecords.map(([l, v]) => [l, ...v.split(';')])]);
      assert.equal(r.status, 0);
    } finally { s.close(); }
    const entry = h.hub.store.list()[0];
    assert.equal(entry.job, 'N-1');
    assert.equal(entry.name, null, '名前は人が付ける');
    assert.deepEqual(entry.eyes, ['R', 'L']);
    assert.deepEqual(entry.check.blockers, []);
    h.hub.store.queue(entry.id, 'D-200');
    const edger = await T.connectDevice('127.0.0.1', h.ports.remote, { connectDelay: 0, timeouts: FAST });
    try {
      const d = await edger.request('EDG', { job: 'D-200', records: [['DEV', 'EDG'], ['VEN', 'DCS'], ['MODEL', 'E']] });
      assert.equal(d.status, 0);
      assert.equal(VCA.value(d.response, 'DBL'), sampleDbl);
      assert.deepEqual(d.response.traces.map(t => t.eye), ['R', 'L'], '玉型は両眼(VCA の玉型として読める)');
    } finally { edger.socket.destroy(); }
  } finally { await h.done(); }
});

test('この規格のトレーサーが壊れた玉型を送ると STATUS=4 で断り、保存しない', async () => {
  const h = await makeHub();
  try {
    const s = await pairAndConnect(h, P.noise.keyPair(), tracerCaps);
    try {
      const r = await s.request('PUT', [['JOB', 'BAD'], ['TRCFMT', '1', '360', 'E', 'R', 'F'], ['R', '1', '2', '3']]);
      assert.equal(r.status, 4);
    } finally { s.close(); }
    assert.equal(h.hub.store.list().length, 0);
  } finally { await h.done(); }
});

test('送り先: vca-hub が機器としてこの規格のホストへ PUT する(相手のフィンガープリントを設定で決める)', async () => {
  const remoteKeys = P.noise.keyPair();
  const got = [];
  let hubKey = null;
  const server = await P.listen(0, {
    keys: remoteKeys, caps: [['VER', '1.0'], ['DEV', 'HST'], ['VEN', 'TEST'], ['MODEL', 'LAB'], ['MAXFRAME', '4096']],
    trust: peer => { hubKey = peer.fingerprint; return true; },
    handlers: { PUT: ({ records }) => { got.push(records); return 0; } },
  });
  const h = await makeHub({
    listeners: [],
    destinations: [{ name: 'ラボ', host: '127.0.0.1', port: server.address().port, protocol: 'oldp', fingerprint: P.noise.fingerprint(remoteKeys.publicKey) }],
  });
  try {
    const e = h.hub.store.saveReceived({ body: sample.replace('REQ=FIL', 'ANS=TRC'), type: 'TRC', job: 'U-1', peer: 't', crcOk: null });
    const r = await h.hub.sendTo(e.id, 'LAB-1', 'ラボ');
    assert.equal(r.status, 0);
    assert.equal(got[0][0][1], 'LAB-1');
    assert.equal(hubKey, h.route('GET', 'peers')({}).host);
    assert.equal(h.hub.store.get(e.id).status, 'sent');
    // フィンガープリントが違えば送らない
    h.hub.cfg.destinations[0].fingerprint = 'XXXX-XXXX-XXXX-XXXX';
    await assert.rejects(h.hub.sendTo(e.id, 'LAB-1', 'ラボ'), err => err.code === 'upload-failed');
  } finally { await h.done(); server.close(); }
});

const wait = ms => new Promise(r => setTimeout(r, ms));
function availSink() { const names = []; return { names, handlers: { AVAIL: ({ records }) => { names.push(records[0][1]); return 0; } } }; }

test('AVAIL: 送信待ちにしたら、つないでいる受け取りの機器へ知らせ、つないだときにも知らせる。受け取らない機器には知らせない', async () => {
  const h = await makeHub();
  try {
    const e1 = h.hub.store.saveReceived({ body: sample.replace('REQ=FIL', 'ANS=TRC'), type: 'TRC', job: 'A-1', peer: 't', crcOk: null });
    h.hub.store.queue(e1.id, 'AV-1');
    const keys = P.noise.keyPair(), tk = P.noise.keyPair();
    const hostFp = h.route('GET', 'peers')({}).host;
    const sink = availSink(), tsink = availSink();
    const open = (k, caps, handlers) => P.connect('127.0.0.1', h.port, { keys: k, caps, handlers, trust: p => p.fingerprint === hostFp });
    await assert.rejects(open(keys, edgerCaps, sink.handlers), e => e.failCode === 3);
    await assert.rejects(open(tk, tracerCaps, tsink.handlers), e => e.failCode === 3);
    for (const k of [keys, tk]) h.route('POST', 'trust')({ body: { fingerprint: P.noise.fingerprint(k.publicKey) } });
    const s = await open(keys, edgerCaps, sink.handlers), t = await open(tk, tracerCaps, tsink.handlers);
    try {
      await wait(350);
      assert.deepEqual(sink.names, ['AV-1'], 'つないだときに、いま送信待ちのものを知らせる');
      const e2 = h.hub.store.saveReceived({ body: sample.replace('REQ=FIL', 'ANS=TRC'), type: 'TRC', job: 'A-2', peer: 't', crcOk: null });
      h.hub.store.queue(e2.id, 'AV-2');
      await wait(100);
      assert.deepEqual(sink.names, ['AV-1', 'AV-2'], '送信待ちにしたら知らせる');
      assert.deepEqual(tsink.names, [], 'トレーサーには知らせない');
      assert.equal(h.route('GET', 'connected')({}).length, 2);
      const ping = await h.route('POST', 'ping')({ body: { fingerprint: P.noise.fingerprint(keys.publicKey) } });
      assert.equal(ping.ok, true);
    } finally { s.close(); t.close(); }
    await wait(50);
    assert.equal(h.route('GET', 'connected')({}).length, 0, '切れたら一覧から消える');
  } finally { await h.done(); }
});

test('AVAIL: つないだときに知らせるのは、新しいほうから 8 個まで', async () => {
  const h = await makeHub();
  try {
    for (let i = 1; i <= 10; i++) {
      const e = h.hub.store.saveReceived({ body: sample.replace('REQ=FIL', 'ANS=TRC'), type: 'TRC', job: `M-${i}`, peer: 't', crcOk: null });
      h.hub.store.queue(e.id, `N-${i}`);
    }
    const keys = P.noise.keyPair();
    const hostFp = h.route('GET', 'peers')({}).host;
    const sink = availSink();
    const open = () => P.connect('127.0.0.1', h.port, { keys, caps: edgerCaps, handlers: sink.handlers, trust: p => p.fingerprint === hostFp });
    await assert.rejects(open(), e => e.failCode === 3);
    h.route('POST', 'trust')({ body: { fingerprint: P.noise.fingerprint(keys.publicKey) } });
    const s = await open();
    try {
      await wait(350);
      assert.deepEqual(sink.names, ['N-10', 'N-9', 'N-8', 'N-7', 'N-6', 'N-5', 'N-4', 'N-3']);
    } finally { s.close(); }
  } finally { await h.done(); }
});

test('PUT: 同じジョブの同じ中身は 2 度目を保存しない。中身が違えば保存する', async () => {
  const h = await makeHub();
  try {
    const s = await pairAndConnect(h, P.noise.keyPair(), tracerCaps);
    try {
      const job = name => [['JOB', name], ['DBL', '18.00'], ['TRCFMT', '1', '3', 'E', 'R', 'F'], ['R', '1', '2', '3']];
      assert.equal((await s.request('PUT', job('D-1'))).status, 0);
      assert.equal((await s.request('PUT', job('D-1'))).status, 0, '2 度目も受け付けたと答える');
      assert.equal(h.hub.store.list().length, 1);
      assert.equal((await s.request('PUT', job('D-2'))).status, 0);
      assert.equal(h.hub.store.list().length, 2, 'ジョブの名前が違えば別のもの');
    } finally { s.close(); }
  } finally { await h.done(); }
});

test('PUT: 受けられない値は STATUS=4 と REJECTED で答え、宣言していない名前空間の項目は捨てて IGNORED で答える', async () => {
  const h = await makeHub();
  try {
    const s = await pairAndConnect(h, P.noise.keyPair(), tracerCaps);
    try {
      const bad = await s.request('PUT', [['JOB', 'V-1'], ['DBL', '18.001']]);
      assert.equal(bad.status, 4);
      assert.deepEqual(bad.records.find(r => r[0] === 'REJECTED'), ['REJECTED', 'DBL']);
      assert.equal(h.hub.store.list().length, 0);
      const ok = await s.request('PUT', [['JOB', 'V-2'], ['DBL', '18.00'], ['ACME:MODE', '2'], ['ZTILT', '1.0']]);
      assert.equal(ok.status, 0);
      assert.deepEqual(ok.records.find(r => r[0] === 'IGNORED'), ['IGNORED', 'ACME:MODE']);
      const body = h.hub.store.readBody(h.hub.store.list()[0]);
      assert.doesNotMatch(body, /ACME:MODE/);
      assert.match(body, /ZTILT=1\.0/, '辞書に無い DCS の項目は残す');
    } finally { s.close(); }
  } finally { await h.done(); }
});

test('加工条件の拡張と一緒に使うと、この規格の加工機へも条件が入る', async () => {
  // 2 つのフォルダの拡張を一度に読めないため、加工条件の例をこの拡張のフォルダの隣へ写して使う
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'oldp-ext-'));
  fs.cpSync(path.join(__dirname, '..', 'oldp'), path.join(dir, 'oldp'), { recursive: true });
  fs.cpSync(path.join(HUB, 'examples', 'extensions', 'processing-conditions'), path.join(dir, 'processing-conditions'), { recursive: true });
  const h2 = await makeHub({ extensionsDir: dir, extensions: { 'oldp': true, 'processing-conditions': {} } });
  try {
    const e = h2.hub.store.saveReceived({ body: sample.replace('REQ=FIL', 'ANS=TRC'), type: 'TRC', job: 'P-1', peer: 't', crcOk: null });
    h2.hub.ext.get('processing-conditions').routes.find(r => r.path === 'conditions' && r.method === 'POST').handler({ body: { id: e.id, conditions: { ETYP: '1', BEVP: '3', BEVM: '1.0', BEVC: '4.00' } } });
    h2.hub.store.queue(e.id, 'PC-1');
    const s = await pairAndConnect(h2, P.noise.keyPair(), edgerCaps);
    try {
      const r = await s.request('GET', [['JOB', 'PC-1']]);
      const v = l => (r.records.find(x => x[0] === l) || []).slice(1).join(';');
      assert.equal(v('ETYP'), '1');
      assert.equal(v('BEVP'), '3;3');
      assert.equal(v('BEVM'), '1.0;1.0');
      assert.equal(v('BEVC'), '4.00;4.00');
      assert.deepEqual(P.records.classify(r.records, { accepts: new Set(edgerCaps.find(x => x[0] === 'LABELS').slice(1)) }).rejected, []);
    } finally { s.close(); }
  } finally { await h2.done(); fs.rmSync(dir, { recursive: true, force: true }); }
});
