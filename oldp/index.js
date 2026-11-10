'use strict';
// vca-hub の拡張: Optical Lab Device Protocol の通信方式。
// 機器(トレーサー・加工機)とこの規格で話し、vca-hub の保管(VCA のテキスト)と名前の仕組みにつなぐ。
//
// 使い方: このフォルダを vca-hub の extensions へ写し(または extensionsDir をこの親のフォルダにし)、config.json に書く。
// 規格の処理は参照実装(optical-lab-device-protocol-reference)の JavaScript を使う(場所は reference.js)。
//   "extensions": { "oldp": true },
//   "listeners": [{ "name": "新しい規格の機器", "port": 33520, "protocol": "oldp" }]
//   送り先(別のホストへ機器として送る): "destinations": [{ "name": "ラボ", "host": "...", "port": 33520, "protocol": "oldp", "fingerprint": "XXXX-XXXX-XXXX-XXXX" }]
// 拡張(規格 11 章): vendors フォルダの .js、または別の vca-hub 拡張から module.exports.vendor() で登録する。
//   { namespace, handle({ records, peer, op, namespace, hub, peers, savePeers }) → STATUS の番号か { records }, setup?(ctx), trusted?(peer, ctx) }
//   登録した名前空間は EXT= で機器に知らせる。待ち受けの settings の require に書いた名前空間は REQUIRE= で機器に求める。
// ペアリング: 知らない機器がつなぐと「ペアリング待ち」に載る。管理画面の「機器のペアリング」でフィンガープリントを機器と見比べ、「信じる」を選ぶ。

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { P } = require('./reference.js');
const hostKey = require('./hostkey.js');
const R = P.records;

const VERSION = '1.0';
const AVAIL_LIMIT = 8;        // つないだときに知らせる送信待ちの数の上限
const PUT_MEMORY = 500;       // 同じ PUT を見分けるために覚えておく数
const EXT_PER_LINE = 8;       // 1 行 80 文字に収まる名前空間の数

// 拡張の登録(名前空間 → 処理)
const vendors = new Map();
function vendor(mod) {
  if (!mod || !/^[A-Z][A-Z0-9]{1,7}$/.test(mod.namespace || '') || typeof mod.handle !== 'function') throw new Error('拡張には namespace(英大文字で始まる英数字 2-8 文字)と handle が要ります');
  vendors.set(mod.namespace, mod);
  return mod;
}
const vendorsDir = path.join(__dirname, 'vendors');
if (fs.existsSync(vendorsDir)) for (const f of fs.readdirSync(vendorsDir).filter(n => n.endsWith('.js'))) vendor(require(path.join(vendorsDir, f)));

/** 名前空間の並びを、1 行に収まるように分けたケイパビリティの行にする */
function listLines(label, names) {
  const out = [];
  for (let i = 0; i < names.length; i += EXT_PER_LINE) out.push([label, ...names.slice(i, i + EXT_PER_LINE)]);
  return out;
}

/** 記録の時刻を、この PC の時刻で月日時分にする */
function localTime(iso) {
  const d = new Date(iso), p = n => String(n).padStart(2, '0');
  return `${p(d.getMonth() + 1)}/${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

/** DCS の値を、この規格の項目に合わせる: ? の項目は送らず、桁の多い小数は末尾の 0 だけ落とす(値は変えない) */
function toProtocol(records) {
  const out = [];
  for (const [label, ...fields] of records) {
    if (fields.some(f => f === '?')) continue;
    const def = R.DICT.labels[label];
    if (def && def.type === 'dec') {
      out.push([label, ...fields.map(f => {
        const m = /^([+-]?\d+)\.(\d+)$/.exec(f);
        if (!m || m[2].length <= def.scale) return f;
        const extra = m[2].slice(def.scale);
        return /^0+$/.test(extra) ? `${m[1]}.${m[2].slice(0, def.scale)}` : f;
      })]);
    } else out.push([label, ...fields]);
  }
  return out;
}

module.exports = {
  title: 'Optical Lab Device Protocol',
  version: VERSION,
  setup(hub) {
    const dir = hub.dataDir;
    const keyFile = path.join(dir, 'host-key.json');
    const peersFile = path.join(dir, 'peers.json');
    // ホストの秘密鍵は暗号化して置く(Windows の DPAPI。hostkey.js)
    const saved = hostKey.loadOrCreate(keyFile, () => P.noise.keyPair().privateKey);
    const keys = P.noise.keyPair(saved.privateKey);
    if (!saved.protected) hub.log('warn', { detail: 'この OS ではホストの秘密鍵を暗号化できないため、ファイルの権限だけで守っています' });
    const fp = P.noise.fingerprint(keys.publicKey);
    // ペアリングした機器と、ペアリング待ちの機器(フィンガープリントごと)
    const peers = fs.existsSync(peersFile) ? JSON.parse(fs.readFileSync(peersFile, 'utf8')) : { trusted: {}, pending: {} };
    const savePeers = () => { const t = peersFile + '.tmp'; fs.writeFileSync(t, JSON.stringify(peers, null, 1)); fs.renameSync(t, peersFile); };
    const who = caps => ({ dev: caps.dev, ven: caps.ven, model: caps.model, sn: caps.sn });
    const hostCaps = [['VER', VERSION], ['DEV', 'HST'], ['VEN', 'vca-hub'], ['MODEL', 'vca-hub'], ['MAXFRAME', '8192']];
    const vendorCtx = { hub, peers, savePeers, noise: P.noise };
    for (const v of vendors.values()) if (v.setup) v.setup(vendorCtx);

    // 同じ PUT を 2 度保存しない(規格 8 章)。ジョブの名前と中身の要約 → 保存した受信データの id
    const putsFile = path.join(dir, 'puts.json');
    const puts = new Map(fs.existsSync(putsFile) ? JSON.parse(fs.readFileSync(putsFile, 'utf8')) : []);
    const savePuts = () => { const t = putsFile + '.tmp'; fs.writeFileSync(t, JSON.stringify([...puts])); fs.renameSync(t, putsFile); };

    // つないでいる機器(フィンガープリント → セッション)。AVAIL と PING に使う
    const connected = new Map();
    const receives = s => s.peer && (s.peer.caps.labels.length > 0 || s.peer.caps.trace);
    const avail = (s, name) => s.request('AVAIL', [['JOB', name]]).catch(() => { /* 切れていれば、次につないだときに知らせる */ });
    hub.on('queued', ({ entry }) => { for (const s of connected.values()) if (receives(s)) avail(s, entry.name); });
    function track(s) {
      s.on('open', peer => {
        connected.set(peer.fingerprint, s);
        const forget = () => { if (connected.get(peer.fingerprint) === s) connected.delete(peer.fingerprint); };
        s.once('close', forget);
        s.once('error', forget);
        s.once('restart', forget);
        if (!receives(s)) return;
        // 機器が受け入れの通知を読み終えるのを待ってから、いま送信待ちのものを知らせる
        const names = hub.store.list().filter(e => e.status === 'queued' && e.name).slice(0, AVAIL_LIMIT).map(e => e.name);   // list() は新しい順
        setTimeout(() => { for (const n of names) avail(s, n); }, 200);
      });
    }

    hub.log('info', { detail: `ホストの鍵のフィンガープリント ${fp}` });

    // ---- 管理画面: ペアリング ----
    hub.page('page.html', '機器のペアリング');
    hub.route('GET', 'peers', () => ({ host: fp, trusted: peers.trusted, pending: peers.pending }));
    hub.route('GET', 'connected', () => [...connected.values()].map(s => ({ fingerprint: s.peer.fingerprint, ...who(s.peer.caps) })));
    hub.route('POST', 'ping', async ({ body }) => {
      const s = connected.get(body.fingerprint);
      if (!s) throw Object.assign(new Error('つながっていません'), { code: 'not-found' });
      const t0 = Date.now();
      await s.request('PING');
      return { ok: true, ms: Date.now() - t0 };
    });
    hub.route('POST', 'trust', ({ body }) => {
      const p = peers.pending[body.fingerprint];
      if (!p) throw Object.assign(new Error('ペアリング待ちにありません'), { code: 'not-found' });
      peers.trusted[body.fingerprint] = { ...p, trustedAt: new Date().toISOString() };
      delete peers.pending[body.fingerprint];
      savePeers();
      hub.log('info', { detail: `機器 ${p.ven} ${p.model} ${p.sn}(${body.fingerprint})をペアリングした` });
      return { ok: true };
    });
    hub.route('POST', 'untrust', ({ body }) => {
      const p = peers.trusted[body.fingerprint] || peers.pending[body.fingerprint];
      delete peers.trusted[body.fingerprint];
      delete peers.pending[body.fingerprint];
      savePeers();
      if (p) hub.log('info', { detail: `機器 ${p.ven} ${p.model}(${body.fingerprint})のペアリングを解除した` });
      return { ok: true };
    });

    // 加工機が捨てた・受けられなかった項目を、受信データごとに残し、詳細と確認の画面に出す(規格 10 章)
    hub.on('describe', ({ entry }) => {
      const d = hub.data.get(entry.id);
      if (!d || !d.results) return [];
      return d.results.slice(-3).map(r => `${localTime(r.at)} ${r.device} STATUS=${r.status}` +
        `${r.ignored.length ? ` 捨てた ${r.ignored.join(',')}` : ''}${r.rejected.length ? ` 受けられない ${r.rejected.join(',')}` : ''}`);
    });

    hub.protocol('oldp', {
      title: 'Optical Lab Device Protocol',

      listen({ name, port, settings }, io) {
        return P.listen(port, socket => {
          if (!io.allowed(socket.remoteAddress)) { io.log('warn', { event: 'rejected', detail: `${socket.remoteAddress} は許可範囲の外` }); return null; }
          const addr = `${socket.remoteAddress}:${socket.remotePort}`.replace(/^::ffff:/, '');
          const delivering = new Map();   // ジョブの名前 → 渡した受信データの id(RESULT を待つ)
          return {
            keys, caps: [...hostCaps, ...listLines('EXT', [...vendors.keys()]), ...listLines('REQUIRE', (settings && settings.require) || [])],
            // シリアルの機器を TCP へ中継してつなぐときは、待ち受けの settings に { "transport": "uart" } と書く
            transport: settings && settings.transport === 'uart' ? 'uart' : 'tcp',
            trust(peer) {
              if (peers.trusted[peer.fingerprint]) {
                for (const v of vendors.values()) if (v.trusted) v.trusted(peer, vendorCtx);
                return true;
              }
              if (!peers.pending[peer.fingerprint]) {
                peers.pending[peer.fingerprint] = { ...who(peer.caps), from: addr, at: new Date().toISOString() };
                savePeers();
              }
              io.log('warn', { event: 'rejected', detail: `ペアリングしていない機器 ${peer.caps.ven} ${peer.caps.model}(${peer.fingerprint})。管理画面の「機器のペアリング」で確かめてください` });
              return false;
            },
            handlers: {
              PUT({ records, peer }) {
                const job = (records.find(r => r[0] === 'JOB') || [])[1];
                if (!job) return 2;
                const ext = new Set(peer.caps.ext);
                const c = R.classify(records, { ext });
                const bad = R.checkTraces(records);
                if (c.rejected.length || bad.length) {
                  io.log('warn', { event: 'upload', job, detail: [...c.reasons, ...bad].join(' / ') });
                  const rejected = bad.length && !c.rejected.includes('TRCFMT') ? [...c.rejected, 'TRCFMT'] : c.rejected;
                  return { records: [['STATUS', '4'], ['REJECTED', ...rejected]] };
                }
                // 宣言していない名前空間の項目は捨てる。辞書に無い DCS の項目は、先の機器が使うかもしれないので残す
                const dropped = c.ignored.filter(l => R.VENDOR.test(l));
                const keep = records.filter(r => r[0] !== 'JOB' && !dropped.includes(r[0]));
                const text = R.format(keep);
                const digest = crypto.createHash('sha256').update(`${job}\0${text}`).digest('hex');
                const known = puts.get(digest);
                if (!known || !hub.store.get(known)) {
                  const e = io.receive({ body: text, job, peer: `${peer.caps.ven} ${peer.caps.model} ${addr}`, type: peer.caps.dev || 'TRC' });
                  puts.delete(digest);
                  puts.set(digest, e.id);
                  while (puts.size > PUT_MEMORY) puts.delete(puts.keys().next().value);
                  savePuts();
                } else io.log('info', { event: 'upload', job, detail: `同じ内容を受信済み(${known})。2 度目は保存しない` });
                return { records: dropped.length ? [['STATUS', '0'], ['IGNORED', ...dropped]] : [['STATUS', '0']] };
              },
              GET({ records, peer }) {
                const job = (records.find(r => r[0] === 'JOB') || [])[1];
                const entry = job && io.queued(job);
                if (!entry) { io.log('warn', { event: 'download', job, result: 'STATUS=1' }); return 1; }
                const c = peer.caps;
                const profile = { labels: c.labels, trcfmt: { fmt: 1, n: (c.trace && c.trace.n) || 0, mode: (c.trace && c.trace.mode) || 'E', eye: 'B' } };
                const out = toProtocol(io.records(entry, { device: who(c), profile }));
                delivering.set(job, entry.id);
                return { records: [['JOB', job], ...out] };
              },
              RESULT({ records, peer }) {
                const v = l => records.filter(r => r[0] === l).flatMap(r => r.slice(1));
                const job = v('JOB')[0];
                const id = job && delivering.get(job);
                if (!id) return 0;
                delivering.delete(job);
                const status = Number(v('STATUS')[0]);
                const device = `${peer.caps.ven} ${peer.caps.model}`;
                const result = { at: new Date().toISOString(), device, status, ignored: v('IGNORED').filter(Boolean), rejected: v('REJECTED').filter(Boolean) };
                const d = hub.data.get(id) || {};
                hub.data.set(id, { ...d, results: (d.results || []).concat(result) });
                if (result.ignored.length || result.rejected.length) {
                  io.log('warn', { event: 'ext', job, detail: `${device} が捨てた ${result.ignored.join(',') || '-'} / 受けられない ${result.rejected.join(',') || '-'}` });
                }
                if (status === 0) io.markSent(id, device);
                return 0;
              },
              INFO({ records }) { io.log('info', { event: 'job-complete', detail: R.format(records).replace(/\r\n/g, ' ').trim() }); return 0; },
              VENDOR({ records, peer, op, namespace }) {
                const v = vendors.get(namespace);
                return v ? v.handle({ records, peer, op, namespace, ...vendorCtx }) : 3;
              },
              TIME() {
                const d = new Date(), p = n => String(n).padStart(2, '0');
                return { records: [['TIME', `${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}`]] };
              },
            },
          };
        }, track, settings && settings.maxHandshakes ? { maxHandshakes: settings.maxHandshakes } : {}).then(server => ({ port: server.address().port, close: () => new Promise(r => server.close(r)) }));
      },

      /** 送り先(この規格のホスト)へ、機器として PUT する。相手のフィンガープリントを設定で決めておく */
      async upload({ dest, name, records }) {
        if (!dest.fingerprint) throw new Error('送り先に fingerprint(相手のホストの鍵のフィンガープリント)がありません');
        const s = await P.connect(dest.host, dest.port, {
          keys, caps: [['VER', VERSION], ['DEV', 'UPL'], ['VEN', 'vca-hub'], ['MODEL', 'vca-hub'], ['MAXFRAME', '8192']],
          trust: peer => peer.fingerprint === dest.fingerprint,
        });
        try {
          const r = await s.request('PUT', [['JOB', name], ...toProtocol(records).filter(x => x[0] !== 'DO')]);
          return { status: r.status === 0 ? 0 : 8, statusText: `相手の STATUS=${r.status}` };
        } finally { s.close(); }
      },
    });
  },
  toProtocol,
  vendor,
};
