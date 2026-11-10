'use strict';
// ホストの秘密鍵の保存。Windows では DPAPI(この PC のいまのユーザーだけが解ける)で暗号化してから書く。
// ほかの OS では暗号化せず、ファイルの権限を所有者だけにする。
const fs = require('node:fs');
const { execFileSync } = require('node:child_process');

const canProtect = process.platform === 'win32';

/** DPAPI の Protect / Unprotect。中身は Base64 で受け渡す(コマンドの引数に秘密を載せない) */
function dpapi(method, b64) {
  const script = 'Add-Type -AssemblyName System.Security;' +
    '$d=[Convert]::FromBase64String([Console]::In.ReadToEnd().Trim());' +
    `$r=[Security.Cryptography.ProtectedData]::${method}($d,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser);` +
    '[Convert]::ToBase64String($r)';
  return execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], { input: b64, encoding: 'ascii', windowsHide: true }).trim();
}

function write(file, privateKey) {
  const body = canProtect
    ? { protection: 'dpapi-user', data: dpapi('Protect', privateKey.toString('base64')) }
    : { protection: 'none', privateKey: privateKey.toString('hex') };
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(body), { mode: 0o600 });
  fs.renameSync(tmp, file);
}

/**
 * 秘密鍵を読む。無ければ generate() で作って書く。暗号化していない形で置かれていれば、暗号化して書き直す。
 * @returns {{ privateKey: Buffer, protected: boolean }}
 */
function loadOrCreate(file, generate) {
  if (!fs.existsSync(file)) {
    const privateKey = generate();
    write(file, privateKey);
    return { privateKey, protected: canProtect };
  }
  const saved = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (saved.protection === 'dpapi-user') return { privateKey: Buffer.from(dpapi('Unprotect', saved.data), 'base64'), protected: true };
  const privateKey = Buffer.from(saved.privateKey, 'hex');
  if (canProtect) write(file, privateKey);
  return { privateKey, protected: canProtect };
}

module.exports = { loadOrCreate };
