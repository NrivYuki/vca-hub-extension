'use strict';
// Optical Lab Device Protocol の参照実装(optical-lab-device-protocol-reference)の JavaScript を読む。
// 環境変数 OLDP_REFERENCE の場所か、このリポジトリの隣のフォルダ(../optical-lab-device-protocol-reference)のものを使う。
const fs = require('node:fs');
const path = require('node:path');

const root = process.env.OLDP_REFERENCE || path.join(__dirname, '..', '..', 'optical-lab-device-protocol-reference');
const entry = path.join(root, 'js', 'src', 'index.js');
if (!fs.existsSync(entry)) throw new Error(`Optical Lab Device Protocol の参照実装が見つかりません(${root})。隣のフォルダに置くか、OLDP_REFERENCE で場所を指定してください`);

module.exports = { root, P: require(entry) };
