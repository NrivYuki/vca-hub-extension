'use strict';
// 標準の拡張 OLDPKEY: 機器の鍵の交換(規格 15 章)。
const OP_CHANGE = 0x80;

module.exports = {
  namespace: 'OLDPKEY',

  handle({ records, peer, op, peers, savePeers, hub, noise }) {
    if (op !== OP_CHANGE) return 3;
    const hex = ((records.find(r => r[0] === 'KEY') || [])[1]) || '';
    if (!/^[0-9a-f]{64}$/.test(hex)) return 4;
    const next = noise.fingerprint(Buffer.from(hex, 'hex'));
    const known = peers.trusted[next];
    if (next === peer.fingerprint || (known && known.replaces !== peer.fingerprint)) return 4;
    const { replaces: _ignored, ...current } = peers.trusted[peer.fingerprint] || {};
    peers.trusted[next] = { ...current, replaces: peer.fingerprint, rotatedAt: new Date().toISOString() };
    savePeers();
    hub.log('info', { detail: `機器の鍵の交換を受け付けた(${peer.fingerprint} → ${next})` });
    return 0;
  },

  /** 新しい鍵でつながったら、前の鍵を信じるのをやめる */
  trusted(peer, { peers, savePeers }) {
    const t = peers.trusted[peer.fingerprint];
    if (!t || !t.replaces) return;
    delete peers.trusted[t.replaces];
    delete t.replaces;
    savePeers();
  },
};
